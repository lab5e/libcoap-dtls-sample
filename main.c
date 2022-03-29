#include <coap2/coap.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "handlers.h"
#include "resolve.h"

#define LOG_LEVEL LOG_NOTICE
#define KEEPALIVE_SECONDS 10
#define BLOCK_MODE (COAP_BLOCK_1)

#define SERVER_ADDR "192.168.1.8"
#define SERVER_PORT 5684

/**
 * Message handler function for CoAP messages received from the server.
 */
static void message_handler(coap_context_t *ctx, coap_session_t *session,
                            coap_pdu_t *sent, coap_pdu_t *received,
                            const coap_tid_t id) {
  switch (COAP_RESPONSE_CLASS(received->code)) {

  case 4:
    // 4xx responses are sent when there's an error with the response, f.e. an
    // unknown resource (4.04), invalid parameters (4.00), access denied
    // (4.01/4.03) or bad options (4.02). In short - the request is invalid and
    // has not been processed.
    printf("Got 4.xx response from server. The request is invalid\n");
    break;

  case 5:
    // 5xx responses are error responses from the server where there's an error
    // on the server side.
    printf("Got 5.xx response from server. Request failed\n");
    break;

  case 2:
    // 2.xx response codes indicates success and the server have received the
    // message.
    printf("Got 2.xx response from server. Request successful\n");
    // Check if there is data waiting
    size_t len = 0;
    uint8_t *data = NULL;
    if (coap_get_data(received, &len, &data) == 0) {
      printf("No data in response\n");
      break;
    }
    if (len > 0) {
      char str[512];
      memset(str, 0, sizeof(str));
      strncpy(str, data, sizeof(str) - 1);
      printf("Got data from server: %s\n", str);
    }

    break;
  default:
    printf("Got response code %d from server. Don't know how to handle it\n",
           received->code);
    break;
  }
}

int main(int argc, char **argv) {
  // Check if DTLS is supported since we'll connect via DTLS.s
  if (!coap_dtls_is_supported()) {
    printf("No DTLS support in libcoap!\n");
    return 1;
  }

  printf("libcoap version is %s\n", LIBCOAP_PACKAGE_VERSION);

  // Initialize the CoAP library
  coap_startup();
  coap_dtls_set_log_level(LOG_LEVEL);
  coap_set_log_level(LOG_LEVEL);

  // Resolve server's address
  coap_address_t server;
  coap_address_init(&server);
  if (!resolve_address(SERVER_ADDR, &server.addr.sa)) {
    printf("Error resolving server address %s\n", SERVER_ADDR);
    return 2;
  }
  server.addr.sin.sin_port = htons(SERVER_PORT);

  // Resolve local interface address
  coap_address_t local;
  coap_address_init(&local);
  if (!resolve_address("0.0.0.0", &local.addr.sa)) {
    printf("Error resolving loopback address\n");
    return 2;
  }

  // Create a context for the session we'll run
  coap_context_t *ctx = coap_new_context(NULL);
  if (!ctx) {
    printf("Could not create CoAP context\n");
    return 1;
  }
  coap_context_set_keepalive(ctx, KEEPALIVE_SECONDS);

  // Create the DTLS session
  coap_dtls_pki_t dtls;
  memset(&dtls, 0, sizeof(dtls));
  dtls.version = COAP_DTLS_PKI_SETUP_VERSION;

  // Note the depth of validation; this is the max number of intermediate and
  // root certificates it will validate before giving up. If you set this to 1
  // the server certificate validation will fail since there is at least
  // one intermediate certificate between the root certificate and the server
  // certificate.

  dtls.verify_peer_cert = 1;        // Verify peer certificate
  dtls.require_peer_cert = 1;       // Require a server certificate
  dtls.allow_self_signed = 1;       // Allow self signed certificate
  dtls.allow_expired_certs = 0;     // No expired certificates
  dtls.cert_chain_validation = 1;   // Validate the chain
  dtls.check_cert_revocation = 0;   // Check the revocation list
  dtls.cert_chain_verify_depth = 2; // Depth of validation.

  dtls.validate_cn_call_back = NULL;  // CN callback (not used)
  dtls.cn_call_back_arg = NULL;       // CN callback
  dtls.validate_sni_call_back = NULL; // SNI callback
  dtls.sni_call_back_arg = NULL;      // SNI callback

  // Set up public key and certificates. Libcoap reads this directly from the
  // file in this version of the library
  dtls.pki_key.key_type = COAP_PKI_KEY_PEM;
  dtls.pki_key.key.pem.public_cert = "cert.crt";
  dtls.pki_key.key.pem.private_key = "key.pem";
  dtls.pki_key.key.pem.ca_file = "cert.crt";

  coap_session_t *session =
      coap_new_client_session_pki(ctx, &local, &server, COAP_PROTO_DTLS, &dtls);

  if (!session) {
    printf("Could not create CoAP session object\n");
    return 2;
  }

  // Register a message handler to process responses from the server.
  coap_register_response_handler(ctx, message_handler);
  coap_register_nack_handler(ctx, nack_handler);
  coap_register_event_handler(ctx, event_handler);

  // Create a new request (aka PDU) that we'll send
  coap_pdu_t *request = coap_new_pdu(session);
  if (!request) {
    printf("Could not create CoAP request\n");
    return 3;
  }

  request->type = COAP_MESSAGE_CON;
  request->tid = coap_new_message_id(session);
  request->code = COAP_REQUEST_POST;

  coap_optlist_t *optlist = NULL;

  const char *path = "mydata";
  char portstr[6];
  sprintf(portstr, "%d", SERVER_PORT);
  coap_insert_optlist(&optlist, coap_new_optlist(COAP_OPTION_URI_PORT,
                                                 coap_opt_length(portstr),
                                                 coap_opt_value(portstr)));
  coap_insert_optlist(&optlist, coap_new_optlist(COAP_OPTION_URI_HOST,
                                                 coap_opt_length(SERVER_ADDR),
                                                 coap_opt_value(SERVER_ADDR)));
  coap_insert_optlist(&optlist, coap_new_optlist(COAP_OPTION_URI_PATH,
                                                 coap_opt_length(path),
                                                 coap_opt_value(path)));

  coap_add_optlist_pdu(request, &optlist);

  // Add the payload to the PDU
  const char *data = "this is the payload";
  coap_add_data(request, sizeof(data), data);

  // Send it
  coap_tid_t tid = coap_send(session, request);
  if (tid == COAP_INVALID_TID) {
    printf("*** Error sending request\n");
  }

  // This loops until there's no more messages to process
  while (!coap_can_exit(ctx)) {
    coap_run_once(ctx, 1000);
  }

  // Release resources
  coap_delete_optlist(optlist);
  coap_session_release(session);
  coap_free_context(ctx);
  coap_cleanup();

  return 0;
}
