#pragma once

/**
 * Low-level event notifications for the CoAP service
 */
int event_handler(coap_context_t *ctx, coap_event_t event,
                  coap_session_t *session);

/**
 * The NACK handler is invoked when a message can't be delivered to the server
 */
void nack_handler(coap_context_t *context, coap_session_t *session,
                  coap_pdu_t *sent, coap_nack_reason_t reason,
                  const coap_tid_t id);