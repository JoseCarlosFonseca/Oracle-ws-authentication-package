create or replace PACKAGE BODY ws_authentication IS
    FUNCTION to_base64 (
        text VARCHAR2
    ) RETURN VARCHAR2 IS
        v_text_raw RAW(32767);
    BEGIN
        v_text_raw := utl_raw.cast_to_raw(text);
        RETURN utl_raw.cast_to_varchar2(utl_encode.base64_encode(v_text_raw));
    END to_base64;

    FUNCTION from_base64 (
        base64 IN VARCHAR2
    ) RETURN VARCHAR2 IS
        v_base64_raw RAW(32767);
    BEGIN
        v_base64_raw := utl_raw.cast_to_raw(base64);
        RETURN utl_raw.cast_to_varchar2(utl_encode.base64_decode(v_base64_raw));
    END from_base64;

    FUNCTION basic (
        username VARCHAR2,
        password VARCHAR2
    ) RETURN VARCHAR2 IS
        v_basic VARCHAR2(2048);
    BEGIN
        v_basic := to_base64(username
                             || ':'
                             || password);
        return('Basic ' || v_basic);
    END basic;

    FUNCTION digest (
        url        IN         VARCHAR2,
        username   IN         VARCHAR2 DEFAULT NULL,
        password   IN         VARCHAR2 DEFAULT NULL,
        realm      IN         VARCHAR2 DEFAULT NULL
    ) RETURN VARCHAR2 IS
    BEGIN
        return('');
    END digest;

FUNCTION hmac (
    ws_name        VARCHAR2,
    ws_operation   VARCHAR2,
    ws_request     VARCHAR2,
    ws_secret      VARCHAR2
) RETURN hmac_request_type IS

    v_systimestamp           TIMESTAMP;
    v_nonce                  NUMBER(16);
    v_post_data              VARCHAR2(2048);
    v_binary_hash            RAW(2048);
    v_path                   VARCHAR2(2048);
    v_binary_path            RAW(2048);
    v_binary_path_and_hash   RAW(2048);
    v_secret_decoded         RAW(2048);
    v_sign                   RAW(2048);
    v_sign_base64            RAW(2048);
    v_api_sign               VARCHAR2(2048);
    v_crlf                   CONSTANT VARCHAR2(2) := chr(13)
                                   || chr(10);
    v_hmac_request           hmac_request_type;
BEGIN
v_systimestamp := systimestamp;
v_nonce := trunc((CAST(v_systimestamp AS DATE) - TO_DATE('01/01/1970', 'dd/mm/yyyy')) * 86400000000) + to_number(substr(TO_CHAR(v_systimestamp, 'ffff'), 1, 6));
    IF ws_request is not null THEN
        v_post_data := ws_request
                       || '&'||'nonce='
                       || TO_CHAR(v_nonce);
    ELSE
        v_post_data := 'nonce=' || TO_CHAR(v_nonce);
    END IF;

    v_binary_hash := dbms_crypto.hash(utl_i18n.string_to_raw(TO_CHAR(v_nonce)
                                                             || v_post_data, 'AL32UTF8'), dbms_crypto.hash_sh256);

    v_path := '/'
              || ws_name
              || '/'
              || ws_operation;
    v_binary_path := utl_i18n.string_to_raw(v_path, 'AL32UTF8');
    v_binary_path_and_hash := v_binary_path || v_binary_hash;
    v_secret_decoded := utl_encode.base64_decode(utl_raw.cast_to_raw(ws_secret));
    v_sign := dbms_crypto.mac(v_binary_path_and_hash, dbms_crypto.hmac_sh512, v_secret_decoded);
    v_sign_base64 := utl_encode.base64_encode(v_sign);
    v_api_sign := utl_raw.cast_to_varchar2(v_sign_base64);
    v_api_sign := replace(v_api_sign, v_crlf); -- remove the CR LF from the api_sign
    v_hmac_request.post_data := v_post_data;
    v_hmac_request.api_sign := v_api_sign;
    RETURN v_hmac_request;
END hmac;

    FUNCTION check_hmac (
        ws_name        VARCHAR2,
        ws_operation   VARCHAR2,
        ws_request     VARCHAR2,
        ws_nonce       NUMBER,
        ws_key         VARCHAR2,
        ws_sign        VARCHAR2
    ) RETURN BOOLEAN IS

        v_secret                 VARCHAR2(2048);
        v_systimestamp           TIMESTAMP;
        v_nonce                  NUMBER(16);
        v_post_data              VARCHAR2(2048);
        v_binary_hash            RAW(2048);
        v_path                   VARCHAR2(2048);
        v_binary_path            RAW(2048);
        v_binary_path_and_hash   RAW(2048);
        v_secret_decoded         RAW(2048);
        v_sign                   RAW(88);
        v_sign_base64            RAW(90);
        v_api_sign               VARCHAR2(90);
        v_crlf                   CONSTANT VARCHAR2(2) := chr(13)
                                       || chr(10);
        v_hmac_request           hmac_request_type;
        v_count                  NUMBER(9);
    BEGIN
        v_nonce := ws_nonce;
        SELECT
            COUNT(*)
        INTO v_count
        FROM
            users
        WHERE
            key = ws_key
            AND nonce < v_nonce + 1000000; --1 second of tolerance

        IF v_count = 1 THEN
            SELECT
                secret
            INTO v_secret
            FROM
                users
            WHERE
                key = ws_key;

            UPDATE users
            SET
                nonce = v_nonce
            WHERE
                key = ws_key;

            COMMIT;
            IF ws_request is not null THEN
                v_post_data := ws_request
                               || '&'||'nonce='
                               || TO_CHAR(v_nonce);
            ELSE
                v_post_data := 'nonce=' || TO_CHAR(v_nonce);
            END IF;

            v_binary_hash := dbms_crypto.hash(utl_i18n.string_to_raw(TO_CHAR(v_nonce)
                                                                     || v_post_data, 'AL32UTF8'), dbms_crypto.hash_sh256);

            v_path := '/'
                      || ws_name
                      || '/'
                      || ws_operation;
            v_binary_path := utl_i18n.string_to_raw(v_path, 'AL32UTF8');
            v_binary_path_and_hash := v_binary_path || v_binary_hash;
            v_secret_decoded := utl_encode.base64_decode(utl_raw.cast_to_raw(v_secret));
            v_sign := dbms_crypto.mac(v_binary_path_and_hash, dbms_crypto.hmac_sh512, v_secret_decoded);
            v_sign_base64 := utl_encode.base64_encode(v_sign);
            v_api_sign := utl_raw.cast_to_varchar2(v_sign_base64);
            v_api_sign := replace(v_api_sign, v_crlf); -- remove the CR LF from the api_sign
            IF v_api_sign = ws_sign THEN
                RETURN true;
            ELSE
                RETURN false;
            END IF;
        ELSE
            RETURN false;
        END IF;

    END check_hmac;

FUNCTION generate_key RETURN VARCHAR2 IS

    crlf    CONSTANT VARCHAR2(2) := chr(13)
                                 || chr(10);
    v_key   VARCHAR2(2048);
BEGIN
    v_key := utl_raw.cast_to_varchar2(utl_encode.base64_encode(utl_raw.cast_to_raw(dbms_crypto.hash(utl_i18n.string_to_raw(dbms_crypto
    .randomnumber, 'AL32UTF8'), dbms_crypto.hash_sh1))));

    v_key := replace(v_key, crlf);
    return   v_key;
    end      generate_key;

    FUNCTION generate_secret RETURN VARCHAR2 IS

        crlf       CONSTANT VARCHAR2(2) := chr(13)
                                     || chr(10);
        v_secret   VARCHAR2(2048);
    BEGIN
        v_secret := utl_raw.cast_to_varchar2(utl_encode.base64_encode(utl_raw.cast_to_raw(dbms_crypto.hash(utl_i18n.string_to_raw
        (dbms_crypto.randomnumber, 'AL32UTF8'), dbms_crypto.hash_sh256))));

        v_secret := replace(v_secret, crlf);
        RETURN v_secret;
    END generate_secret;

    FUNCTION create_user (
        v_username VARCHAR2
    ) RETURN NUMBER IS
        v_id users.id%TYPE;
    BEGIN
        INSERT INTO users (
            username,
            key,
            secret,
            creation_date,
            nonce
        ) VALUES (
            'Jose',
            generate_key,
            generate_secret,
            external_ws.to_unix_timestamp(SYSDATE),
            0
        ) RETURNING id INTO v_id;

        RETURN v_id;
    END create_user;

END ws_authentication;
