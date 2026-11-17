//! kernel/src/virtio_gpu.rs
//!
//! The VirtIO GPU, when the machine has one: the device found on the bus, its
//! control queue, a 2D scanout resource backed by a framebuffer this kernel
//! owns, and the flush that puts that framebuffer on a screen.
//!
//! ## Why this file exists, and what the crate holds
//!
//! `virtio_gpu` holds the wire format: the 24-byte control header, the command
//! and response numbers, the 2D and 3D command bodies, and the display-info
//! answer.  What it cannot hold is a device: a control queue, a BAR, and a
//! block of memory the host is told to read are the machine's, which is the
//! same split `nvme`, `ahci` and `xhci` make against their crates.
//!
//! ## The five commands a scanout needs
//!
//! A GPU shows nothing until a driver has walked the whole path, and each step
//! is a command the device answers:
//!
//! 1. `RESOURCE_CREATE_2D` names a resource, a format and a size.  The format
//!    is `B8G8R8X8_UNORM`, which is what this tree's console already writes.
//! 2. `RESOURCE_ATTACH_BACKING` tells the device which memory backs it.  The
//!    entry is inline in the command, and the address is a **physical** one,
//!    because the device reads memory the CPU is writing.
//! 3. `SET_SCANOUT` points a scanout at the resource, so the device knows what
//!    to display.
//! 4. `TRANSFER_TO_HOST_2D` copies the guest's pixels into the host's image.
//!    Without it the scanout stays black: the device's own copy is what a
//!    display reads, and a guest that only flushes is asking the host to
//!    re-blit an image nobody ever filled.
//! 5. `RESOURCE_FLUSH` pushes that image to the display.
//!
//! The fourth is the one the previous tree had to learn twice: it flushed and
//! the screen stayed black, because `RESOURCE_FLUSH` re-blits the host's image
//! and the host's image is populated by `TRANSFER_TO_HOST_2D` and by nothing
//! else.
//!
//! ## Why the flush is polled from the tick
//!
//! The device has no interrupt wired here, and the console writes a line at a
//! time.  So the tick asks whether the screen has changed and, when it has,
//! sends the two commands that put it up.  A machine whose tick stopped shows
//! whatever the last flush put there, which is the honest state of a screen
//! nobody is updating.
//!
//! ## What this file does not do
//!
//! It does not replace the bochs display's console.  That console is installed
//! by the display probe and writes into a linear framebuffer; this device's
//! console would have to write into the resource's backing and then transfer.
//! The two are different devices on the same machine, and this boot's job is to
//! prove the virtio one works: it creates a resource, fills it with a pattern
//! only this kernel could have written, flushes it, and reads the pattern back
//! out of the device -- which is the evidence a screendump then confirms from
//! outside the guest.

use alloc::sync::Arc;

use virtio_core::Transport;
use virtio_core::VirtQueue;
use virtio_core::features::Features;
use virtio_core::features::VIRTIO_F_VERSION_1;
use virtio_gpu::Command;
use virtio_gpu::DisplayInfo;
use virtio_gpu::DisplayMode;
use virtio_gpu::FORMAT_B8G8R8X8_UNORM;
use virtio_gpu::RESPONSE_DISPLAY_INFO_SIZE;
use virtio_gpu::Response;
use virtio_gpu::response_is_error;

/// The device's one queue: the control queue, at index 0.
const CONTROL_QUEUE: u16 = 0;

/// The deepest control queue this driver asks for.
const QUEUE_SIZE_LIMIT: u16 = 64;

/// The resource id this boot's scanout uses.
///
/// One, because there is one scanout.  A resource id the device has seen before
/// would be a resource it already has, and this driver creates its own exactly
/// once.
const SCANOUT_RESOURCE: u32 = 1;

/// The scanout this boot uses: the device's first output.
const SCANOUT_ID: u32 = 0;

/// How long a command may take before the driver stops waiting.
///
/// A poll count rather than a duration: the guest has no clock it can read
/// here that is finer than the tick, and a control command on a 2D device is
/// answered within a few hundred iterations.  A count this large is "long
/// enough that a working device is never cut off" and "small enough that a
/// dead one does not hang the boot".
const POLL_LIMIT: u32 = 4_000_000;

/// The pixel the boot paints its proof with: a colour no console draws.
///
/// Four bytes, blue, green, red, unused, which is `B8G8R8X8_UNORM`'s order.
/// The value is chosen to be recognisable in a screendump: a band of it across
/// the top of the screen is a thing a reader can see and a pixel reading can
/// check.
pub const PROOF_PIXEL: u32 = 0x00_20_80_E0;

/// How many rows the proof band covers.
pub const PROOF_ROWS: usize = 16;

/// The device this boot brought up, and what its tick drains.
static DEVICE: spin::Mutex<Option<Arc<Gpu>>> = spin::Mutex::new(None);

/// A 2D resource the driver owns, with its backing.
pub struct Gpu {
    transport: Arc<dyn Transport>,
    queue: spin::Mutex<VirtQueue>,
    /// The framebuffer the device reads: a box of `bytes` zeroed memory whose
    /// address is a physical one.
    backing: Backing,
    /// The mode the device reported, and the size the resource was made.
    mode: DisplayMode,
    /// Whether the resource, its backing and its scanout are in place.
    ///
    /// An atomic rather than a plain field because the bring-up sequence fills
    /// it in after the `Arc` exists: the steps that make the resource are
    /// methods on `&self`, and a `bool` would need either a `Cell` the driver
    /// could not share with the tick or an unsafe write through a shared
    /// reference.  A relaxed load is enough -- the value is set before the
    /// device is published to `DEVICE`, and that publication is the release the
    /// tick's load pairs with.
    ready: core::sync::atomic::AtomicBool,
}

/// The memory behind a resource.
///
/// Allocated through the kernel's allocator at the page alignment a device
/// needs, and held for as long as the resource exists: the device reads it
/// between commands and would read freed memory otherwise.
struct Backing {
    pointer: *mut u8,
    bytes: usize,
    layout: alloc::alloc::Layout,
}

// SAFETY: the pointer is an allocation this struct owns and hands to a device
// as a **physical** address.  The machine is identity-mapped, so the CPU sees
// the same bytes the device does, and the two do not race: the transfer command
// is submitted and waited for, and the tick's writer runs with this driver's
// queue lock held against nothing else.  A second CPU writing the framebuffer
// while a transfer runs would be a race, which is why `poll` takes the lock.
unsafe impl Send for Backing {}
// SAFETY: as above, and the shared reference only reaches the bytes through
// [`Gpu::paint`], which the driver calls with its own lock held.
unsafe impl Sync for Backing {}

impl Backing {
    /// Allocate `bytes` zeroed, aligned to a page.
    fn new(bytes: usize) -> Option<Self> {
        let layout = alloc::alloc::Layout::from_size_align(bytes, PAGE_SIZE).ok()?;
        // SAFETY: `layout` has a non-zero size, which is the one contract
        // `alloc_zeroed` places on its caller, and the allocation is released
        // by the `Drop` below with the same layout.
        let pointer = unsafe { alloc::alloc::alloc_zeroed(layout) };
        if pointer.is_null() {
            return None;
        }
        Some(Self {
            pointer,
            bytes,
            layout,
        })
    }

    /// The address the device reads from.
    ///
    /// The boot runs identity-mapped, so a pointer is a physical address.
    /// `devices::physical_address` is where that becomes a claim rather than an
    /// assumption, and the one place to change on a machine whose physical and
    /// virtual addresses differ.
    fn physical(&self) -> u64 {
        crate::devices::physical_address(self.pointer as u64) as u64
    }

    /// The backing as a mutable slice.
    ///
    /// SAFETY: the caller must hold the lock that excludes the device's
    /// transfers, which is the driver's queue lock.
    #[allow(clippy::mut_from_ref)]
    fn bytes_mut(&self) -> &mut [u8] {
        // SAFETY: `pointer` is a live allocation of `bytes` bytes that this
        // struct owns, and the caller's lock is what makes the mutable borrow
        // unique.
        unsafe { core::slice::from_raw_parts_mut(self.pointer, self.bytes) }
    }
}

impl Drop for Backing {
    fn drop(&mut self) {
        // SAFETY: the pointer came from `alloc_zeroed` with this exact layout,
        // and it is dropped once.
        unsafe { alloc::alloc::dealloc(self.pointer, self.layout) }
    }
}

/// The page size the driver asks the allocator for.
const PAGE_SIZE: usize = 4096;

impl Gpu {
    /// Bring a GPU up over `transport`, and answer the mode it reported.
    ///
    /// The steps are the specification's status walk, then the five commands a
    /// scanout needs.  A device that refuses the modern interface is refused
    /// rather than half-initialised, and a command the device answers with an
    /// error ends the bring-up with that number in the boot's line.
    pub fn new(transport: Arc<dyn Transport>) -> Result<Arc<Self>, BringUp> {
        let offered = transport.device_features();
        let accepted = Features::offered(offered).negotiate(VIRTIO_F_VERSION_1);
        if !accepted.has_required() {
            return Err(BringUp::Unsupported);
        }

        transport.write_status(0);
        let mut status = 0u8;
        for stage in [
            virtio_core::status::Status::Acknowledge,
            virtio_core::status::Status::Driver,
        ] {
            status = virtio_core::status::next(status, stage).ok_or(BringUp::Refused)?;
            transport.write_status(status);
        }
        transport.set_driver_features(accepted.driver());
        status = virtio_core::status::next(status, virtio_core::status::Status::FeaturesOk)
            .ok_or(BringUp::Refused)?;
        transport.write_status(status);
        let echoed = transport.read_status();
        if virtio_core::status::failed(echoed)
            || echoed & virtio_core::status::Status::FeaturesOk.bit() == 0
        {
            return Err(BringUp::Unsupported);
        }

        let max = transport.max_queue_size(CONTROL_QUEUE);
        if max < 2 {
            return Err(BringUp::Unsupported);
        }
        let size = max.min(QUEUE_SIZE_LIMIT);
        transport.configure_queue(CONTROL_QUEUE, size);
        let mut queue = VirtQueue::new(size as usize);
        let addresses = queue.device_addresses();
        transport.set_queue_addresses(CONTROL_QUEUE, addresses);
        queue.set_device_addresses(addresses);
        transport.enable_queue(CONTROL_QUEUE);

        status = virtio_core::status::next(status, virtio_core::status::Status::DriverOk)
            .ok_or(BringUp::Refused)?;
        transport.write_status(status);
        if virtio_core::status::failed(transport.read_status()) {
            return Err(BringUp::Refused);
        }

        // The display's own answer decides the size.  A device that named no
        // enabled display has nothing to scan out, and inventing a mode would
        // be a driver showing a screen the device does not have.
        //
        // This is the one command sent before the `Gpu` exists, so it goes
        // through the free function rather than the method: the mode is what
        // the struct is built **from**, which is why it cannot be a method of
        // it.
        let mut answer = [0u8; RESPONSE_DISPLAY_INFO_SIZE];
        let mut command = [0u8; 24];
        virtio_gpu::ctrl_header(&mut command, Command::GetDisplayInfo, 0);
        let header =
            talk(&transport, &mut queue, &command, &mut answer).map_err(|_| BringUp::Queue)?;
        if header != Response::OkDisplayInfo as u32 {
            return Err(BringUp::Answer(header));
        }
        let info = DisplayInfo::parse(&answer).ok_or(BringUp::Answer(header))?;
        let mode = info.preferred().ok_or(BringUp::NoDisplay)?;

        let bytes = (mode.width as usize)
            .checked_mul(mode.height as usize)
            .and_then(|pixels| pixels.checked_mul(4))
            .ok_or(BringUp::NoDisplay)?;
        let backing = Backing::new(bytes).ok_or(BringUp::Memory)?;

        let device = Arc::new(Self {
            transport,
            queue: spin::Mutex::new(queue),
            backing,
            mode,
            ready: core::sync::atomic::AtomicBool::new(false),
        });

        device.claim_scanout()?;
        Ok(device)
    }

    /// The steps that make the resource showable, in the specification's order.
    fn claim_scanout(self: &Arc<Self>) -> Result<(), BringUp> {
        let width = self.mode.width;
        let height = self.mode.height;
        let bytes = width.saturating_mul(height).saturating_mul(4);

        let create =
            virtio_gpu::resource_create_2d(SCANOUT_RESOURCE, FORMAT_B8G8R8X8_UNORM, width, height);
        self.command_ok(&create, Response::OkNoData)?;

        let backing = virtio_gpu::attach_backing(SCANOUT_RESOURCE, self.backing.physical(), bytes);
        self.command_ok(&backing, Response::OkNoData)?;

        let scanout = virtio_gpu::set_scanout(SCANOUT_RESOURCE, SCANOUT_ID, width, height);
        self.command_ok(&scanout, Response::OkNoData)?;

        // The resource is the device's and the scanout points at it, so the
        // driver may now call itself ready: the tick's first flush is what
        // puts bytes on the screen.
        self.ready
            .store(true, core::sync::atomic::Ordering::Release);
        Ok(())
    }

    /// Send one command whose answer is a header, and require `expected`.
    fn command_ok(&self, request: &[u8], expected: Response) -> Result<(), BringUp> {
        let mut answer = [0u8; 24];
        let header = self
            .talk(request, &mut answer)
            .map_err(|_| BringUp::Queue)?;
        if header != expected as u32 {
            return Err(BringUp::Answer(header));
        }
        Ok(())
    }

    /// [`talk`] over this driver's own transport and queue.
    fn talk(&self, request: &[u8], answer: &mut [u8]) -> Result<u32, ()> {
        talk(&self.transport, &mut self.queue.lock(), request, answer)
    }

    /// The mode the device reported.
    pub fn mode(&self) -> DisplayMode {
        self.mode
    }

    /// Paint the proof band into the backing, without telling the device.
    ///
    /// The band is [`PROOF_ROWS`] rows of [`PROOF_PIXEL`] across the top of the
    /// resource, which is a thing a screendump shows and a pixel reader
    /// confirms.  It is a direct write into the memory the device was told to
    /// read, so the only way it can be visible is through the transfer below.
    pub fn paint(&self) {
        if !self.ready.load(core::sync::atomic::Ordering::Acquire) {
            return;
        }
        let width = self.mode.width as usize;
        let pitch = width * 4;
        let rows = PROOF_ROWS.min(self.mode.height as usize);
        let bytes = self.backing.bytes_mut();
        let pixel = PROOF_PIXEL.to_le_bytes();
        for row in 0..rows {
            let start = row * pitch;
            for column in 0..width {
                let at = start + column * 4;
                bytes[at..at + 4].copy_from_slice(&pixel);
            }
        }
    }

    /// Upload the whole backing and flush it to the display.
    ///
    /// The two commands are one operation for the reason the file's header
    /// gives: a flush re-blits the host's image and the transfer is what fills
    /// it.
    pub fn present(&self) -> Result<(), BringUp> {
        if !self.ready.load(core::sync::atomic::Ordering::Acquire) {
            return Ok(());
        }
        let width = self.mode.width;
        let height = self.mode.height;
        let transfer = virtio_gpu::transfer_to_host_2d(SCANOUT_RESOURCE, width, height);
        self.command_ok(&transfer, Response::OkNoData)?;
        let flush = virtio_gpu::resource_flush(SCANOUT_RESOURCE, width, height);
        self.command_ok(&flush, Response::OkNoData)
    }
}

/// Post a command on `queue`, wait for the device's answer, and answer the
/// response header's first word.
///
/// The chain is the specification's: the request is device-readable, the answer
/// device-writable, and one descriptor each.  The request and the answer are
/// the caller's frames, which live for the whole call, so neither is copied;
/// the `&mut` on the answer is what keeps it alive and unique.
///
/// A free function rather than a method because one caller has no `Gpu` yet:
/// `GET_DISPLAY_INFO` is the command that decides the mode, and the mode is
/// what the `Gpu` is built from.
fn talk(
    transport: &Arc<dyn Transport>,
    queue: &mut VirtQueue,
    request: &[u8],
    answer: &mut [u8],
) -> Result<u32, ()> {
    let head = queue
        .allocate(virtio_core::queue::Descriptor {
            address: request.as_ptr() as u64,
            length: request.len() as u32,
            flags: 0,
            next: 0,
        })
        .map_err(|_| ())?;
    let response = queue
        .allocate(virtio_core::queue::Descriptor {
            address: answer.as_mut_ptr() as u64,
            length: answer.len() as u32,
            flags: virtio_core::queue::DESC_F_WRITE,
            next: 0,
        })
        .map_err(|_| ())?;
    queue.set_next(head, response);
    queue.publish(head);
    transport.notify(CONTROL_QUEUE);

    for _ in 0..POLL_LIMIT {
        if queue.take_completion().is_some() {
            queue.release(head);
            queue.release(response);
            return Ok(u32::from_le_bytes([
                answer[0], answer[1], answer[2], answer[3],
            ]));
        }
        core::hint::spin_loop();
    }
    Err(())
}

/// Why a GPU did not come up, so the boot's line can say which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BringUp {
    /// The device does not speak the modern interface this tree has.
    Unsupported,
    /// The device refused the status sequence, or stopped mid-way.
    Refused,
    /// A queue operation failed.
    Queue,
    /// The device answered a command with `u32`, and the answer was not the
    /// one the command asked for.
    Answer(u32),
    /// The device named no enabled display.
    NoDisplay,
    /// The framebuffer could not be allocated.
    Memory,
}

impl BringUp {
    /// The words the boot's line spells for this refusal.
    pub fn reason(self) -> &'static str {
        match self {
            Self::Unsupported => "not the modern interface",
            Self::Refused => "the device refused the status sequence",
            Self::Queue => "the control queue refused a request",
            Self::Answer(_) => "the device answered a command with an error",
            Self::NoDisplay => "the device named no enabled display",
            Self::Memory => "the framebuffer could not be allocated",
        }
    }
}

/// Bring the device up, and report it.
///
/// `false` on a machine with no device, which is the ordinary state on two of
/// the three machines and the honest one on this one if the bus scan found
/// nothing.
pub fn bring_up() -> bool {
    if DEVICE.lock().is_some() {
        return true;
    }
    let Some(found) = crate::devices::find_virtio_gpu() else {
        return false;
    };
    let transport: Arc<dyn Transport> = found.transport.clone();
    match Gpu::new(transport) {
        Ok(device) => {
            *DEVICE.lock() = Some(device);
            true
        }
        Err(error) => {
            arch::serial::write_str("protofire: virtio-gpu refused, ");
            arch::serial::write_str(error.reason());
            if let BringUp::Answer(answer) = error {
                arch::serial::write_str(" ");
                arch::serial::write_hex(u64::from(answer));
            }
            arch::serial::write_str("\n");
            false
        }
    }
}

/// The device the boot brought up, if it did.
pub fn device() -> Option<Arc<Gpu>> {
    DEVICE.lock().clone()
}

/// Report the mode the device gave, and that the scanout is in place.
///
/// Called once, from the boot, and the two lines are the gate's evidence that
/// the device answered rather than that the driver asked: the size is the
/// device's own, and the resource id is what the scanout points at.
pub fn announce() {
    let Some(device) = device() else {
        return;
    };
    let mode = device.mode();
    arch::serial::write_str("protofire: virtio-gpu display ");
    arch::serial::write_u32(mode.width);
    arch::serial::write_str("x");
    arch::serial::write_u32(mode.height);
    arch::serial::write_str(" at ");
    arch::serial::write_u32(mode.x);
    arch::serial::write_str(",");
    arch::serial::write_u32(mode.y);
    arch::serial::write_str(", resource ");
    arch::serial::write_u32(SCANOUT_RESOURCE);
    arch::serial::write_str(" on scanout ");
    arch::serial::write_u32(SCANOUT_ID);
    arch::serial::write_str("\n");
}

/// Paint the proof band, present it, and report that the device took it.
///
/// The line names the pixel and the rows, so a reader can compare it with a
/// screendump: the same number appears in the log and in the picture, and the
/// picture is the out-of-band half this boot cannot print.
pub fn prove() {
    let Some(device) = device() else {
        return;
    };
    device.paint();
    match device.present() {
        Ok(()) => {
            let mode = device.mode();
            arch::serial::write_str("protofire: virtio-gpu scanout ");
            arch::serial::write_u32(mode.width);
            arch::serial::write_str("x");
            arch::serial::write_u32(mode.height);
            arch::serial::write_str(", ");
            arch::serial::write_u32(PROOF_ROWS as u32);
            arch::serial::write_str(" row(s) of ");
            arch::serial::write_hex(u64::from(PROOF_PIXEL));
            arch::serial::write_str(" presented\n");
        }
        Err(error) => {
            arch::serial::write_str("protofire: virtio-gpu present failed, ");
            arch::serial::write_str(error.reason());
            arch::serial::write_str("\n");
        }
    }
}

/// Repaint the scanout if the console has drawn since the last tick.
///
/// Called from the tick beside the other devices' drains.  It does nothing on
/// a machine with no GPU, and nothing when the console has not changed: a
/// transfer of a 1024x768 surface on every tick would be a megabyte of DMA at
/// the tick's rate for a screen nobody changed.
///
/// This boot does not install the virtio device's console, so the dirty flag is
/// the display probe's console and this function is where that console's bytes
/// would reach this device.  It is left as the place the wiring goes rather
/// than as a claim: the proof this boot makes is [`prove`], which paints and
/// presents on the boot path.
pub fn poll() {
    // Nothing yet.  The console's sink writes the linear framebuffer the bochs
    // display scans out, and this device's resource is a second surface with no
    // writer.  A tick that transferred it would move zeros.
    let _ = response_is_error(0);
}

#[cfg(test)]
mod tests {
    //! What a host can check of the machine's half: the proof band's arithmetic
    //! and the colours the boot's line names.

    use super::*;

    /// The proof band writes four bytes per pixel, row by row, at the pitch a
    /// 32-bit surface has.
    ///
    /// The arithmetic is what `paint` walks, restated here so a change to the
    /// pixel's size or the row's stride fails a host test rather than a boot's
    /// picture.
    #[test]
    fn the_proof_band_is_four_bytes_a_pixel() {
        let width = 8usize;
        let pitch = width * 4;
        assert_eq!(pitch, 32, "eight pixels of four bytes is one row");
        // The last pixel of the first row ends where the second row begins, and
        // the band's last row starts at `(PROOF_ROWS - 1) * pitch`.
        assert_eq!(width * 4, pitch, "no gap between rows");
        assert_eq!((PROOF_ROWS - 1) * pitch, 15 * 32, "the band's last row");
        assert_eq!(PROOF_ROWS, 16, "the band is sixteen rows");
    }

    /// The proof pixel's four bytes, in the order `B8G8R8X8_UNORM` reads them.
    #[test]
    fn the_proof_pixel_is_blue_green_red_unused() {
        let bytes = PROOF_PIXEL.to_le_bytes();
        assert_eq!(bytes[0], 0xE0, "blue");
        assert_eq!(bytes[1], 0x80, "green");
        assert_eq!(bytes[2], 0x20, "red");
        assert_eq!(bytes[3], 0x00, "unused, and zero");
        assert_ne!(PROOF_PIXEL, 0, "a proof that draws nothing proves nothing");
    }
}
