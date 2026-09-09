use core::task::{Context, Poll};

use hisi_rf_core::l2::{L2Port, QueueDiagnostics, QueueError};

use super::{CallbackRoute, Registration, RouteError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkError {
    Route(RouteError),
    Queue(QueueError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmitError<E> {
    Native(E),
    StaleGeneration,
    AdmissionClosed,
}

/// Session/TX owner for the native worker. It owns no packet buffers and is not
/// shared with the network executor. The executor owns the unique L2Device.
pub struct NativeLink<'route, 'storage, const RX: usize, const TX: usize, const MTU: usize> {
    port: L2Port<'storage, RX, TX, MTU>,
    registration: Registration<'route, 'storage, RX, MTU>,
}

impl<'route, 'storage, const RX: usize, const TX: usize, const MTU: usize>
    NativeLink<'route, 'storage, RX, TX, MTU>
{
    /// Bind a down port to the sole native callback registration.
    pub fn bind(
        mut port: L2Port<'storage, RX, TX, MTU>,
        route: &'route CallbackRoute<'storage, RX, MTU>,
    ) -> Result<Self, LinkError> {
        let registration = route.claim(port.ingress()).map_err(LinkError::Route)?;
        port.link_down().map_err(LinkError::Queue)?;
        Ok(Self { port, registration })
    }

    /// Establish a new epoch only after native RX/TX from the old epoch has
    /// quiesced. Rust-ticket drainage is checked here; vendor drainage is a
    /// separate prerequisite to be implemented by the WS63 lifecycle owner.
    pub fn begin_after_native_quiescence(&mut self) -> Result<(), LinkError> {
        let intent = self.registration.prepare_open().map_err(LinkError::Route)?;
        // Network wakeups run outside the lock. A newer native close during
        // this window must win over this open, including TX queued by a wake.
        let generation = self.port.begin_session().map_err(LinkError::Queue)?;
        if let Err(error) = self.registration.commit_open(intent, generation) {
            self.port.link_down().map_err(LinkError::Queue)?;
            return Err(LinkError::Route(error));
        }
        Ok(())
    }

    /// Close RX admission first, then invalidate network tokens/queued frames.
    /// This does not wait for an outstanding native send or drain vendor DMA.
    pub fn close(&mut self) -> Result<(), QueueError> {
        self.registration.close();
        self.port.link_down()
    }

    /// At most one frame is submitted per worker step. The caller must execute
    /// this in normal worker context, never in an IRQ or critical section.
    ///
    /// The native function must copy the frame or finish reading it before
    /// returning. Ok acknowledges that boundary, not delivery over the air.
    /// Native rejection drops explicitly; it cannot silently credit delivery.
    pub fn poll_transmit<E>(
        &mut self,
        cx: &mut Context<'_>,
        submit: impl FnOnce(&[u8]) -> Result<(), E>,
    ) -> Poll<Result<(), SubmitError<E>>> {
        let Some(packet) = self.port.transmit(cx) else {
            return Poll::Pending;
        };
        if !packet.is_current() {
            return Poll::Ready(Err(SubmitError::StaleGeneration));
        }
        let Some(_ticket) = self.registration.enter_transmit(packet.generation()) else {
            return Poll::Ready(Err(SubmitError::AdmissionClosed));
        };
        if let Err(error) = submit(packet.frame()) {
            return Poll::Ready(Err(SubmitError::Native(error)));
        }
        Poll::Ready(packet.complete().map_err(|_| SubmitError::StaleGeneration))
    }

    pub fn rx_diagnostics(&self) -> QueueDiagnostics {
        self.port.rx_diagnostics()
    }

    pub fn tx_diagnostics(&self) -> QueueDiagnostics {
        self.port.tx_diagnostics()
    }
}

impl<const RX: usize, const TX: usize, const MTU: usize> Drop for NativeLink<'_, '_, RX, TX, MTU> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
