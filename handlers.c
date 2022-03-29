#include <coap2/coap.h>
#include <stdio.h>

int event_handler(coap_context_t *ctx, coap_event_t event,
                  coap_session_t *session) {
  switch (event) {
  case COAP_EVENT_DTLS_CLOSED:
    printf("Event: DTLS closed\n");
    break;
  case COAP_EVENT_DTLS_CONNECTED:
    printf("Event: DTLS connected\n");
    break;
  case COAP_EVENT_DTLS_RENEGOTIATE:
    printf("Event: DTLS renegotiate\n");
    break;
  case COAP_EVENT_DTLS_ERROR:
    printf("Event: DTLS error\n");
    break;
  case COAP_EVENT_TCP_CONNECTED:
    printf("Event: TCP connected\n");
    break;
  case COAP_EVENT_TCP_CLOSED:
    printf("Event: TCP closed\n");
    break;
  case COAP_EVENT_TCP_FAILED:
    printf("Event: TCP failed\n");
    break;
  case COAP_EVENT_SESSION_CONNECTED:
    printf("Event: Session connected\n");
    break;
  case COAP_EVENT_SESSION_CLOSED:
    printf("Event: Session closed\n");
    break;
  case COAP_EVENT_SESSION_FAILED:
    printf("Event: Session failed\n");
    break;
  default:
    printf("Uknown CoAP event: %04x\n", event);
    break;
  }
  return 0;
}

void nack_handler(coap_context_t *context, coap_session_t *session,
                  coap_pdu_t *sent, coap_nack_reason_t reason,
                  const coap_tid_t id) {
  switch (reason) {
  case COAP_NACK_TOO_MANY_RETRIES:
    printf("CoAP NACK handler: reason: too many retries id=%d\n", id);
    break;
  case COAP_NACK_NOT_DELIVERABLE:
    printf("CoAP NACK handler: reason: not deliverable id=%d\n", id);
    break;
  case COAP_NACK_RST:
    printf("CoAP NACK handler: reason: RST id=%d\n", id);
    break;
  case COAP_NACK_TLS_FAILED:
    printf("CoAP NACK handler: reason: TLS failed id=%d\n", id);
    break;
  default:
    printf("CoAP NACK handler: reason=%d id=%d\n", reason, id);
    break;
  }
}
