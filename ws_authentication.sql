create or replace PACKAGE ws_authentication IS
    TYPE hmac_request_type IS RECORD (
        post_data VARCHAR2(2048),
        api_sign VARCHAR2(88)
    );
    FUNCTION to_base64 (
        text VARCHAR2
    ) RETURN VARCHAR2;

    FUNCTION from_base64 (
        base64 IN VARCHAR2
    ) RETURN VARCHAR2;

    FUNCTION basic (
        username VARCHAR2,
        password VARCHAR2
    ) RETURN VARCHAR2;

    FUNCTION digest (
        url        IN         VARCHAR2,
        username   IN         VARCHAR2 DEFAULT NULL,
        password   IN         VARCHAR2 DEFAULT NULL,
        realm      IN         VARCHAR2 DEFAULT NULL
    ) RETURN VARCHAR2;

    FUNCTION hmac (
        ws_name        VARCHAR2,
        ws_operation   VARCHAR2,
        ws_request     VARCHAR2,
        ws_secret      VARCHAR2
    ) RETURN hmac_request_type;

    FUNCTION check_hmac (
        ws_name        VARCHAR2,
        ws_operation   VARCHAR2,
        ws_request     VARCHAR2,
        ws_nonce       NUMBER,
        ws_key         VARCHAR2,
        ws_sign        VARCHAR2
    ) RETURN BOOLEAN;

    FUNCTION generate_key RETURN VARCHAR2;

    FUNCTION generate_secret RETURN VARCHAR2;

    FUNCTION create_user (
        v_username VARCHAR2
    ) RETURN NUMBER;

END ws_authentication;
