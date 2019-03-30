create or replace PACKAGE BODY test_ws_authentication IS

    PROCEDURE basic IS
    BEGIN
        dbms_output.put_line(ws_authentication.basic('scott', 'tiger'));
    END basic;

    PROCEDURE from_base64 IS
    BEGIN
        dbms_output.put_line(ws_authentication.from_base64('c2NvdHQ6dGlnZXI='));
    END from_base64;

    PROCEDURE hmac IS
        v_hmac_request ws_authentication.hmac_request_type;
    BEGIN
        v_hmac_request := ws_authentication.hmac('sessions', 'active', '', 'NTYzNTk2RkQ0MTg1NDk5NjUyRDkwQUJFM0IwRENEODA0RDFEMUE4RDYxRTA4N0ZCNzA2RjUwNUIzOEM5NDM2Nw==');
        dbms_output.put_line(v_hmac_request.post_data);
        dbms_output.put_line(v_hmac_request.api_sign);
    END hmac;

    PROCEDURE check_hmac IS

        v_hmac_request   ws_authentication.hmac_request_type;
        v_user_ok        BOOLEAN := false;
        v_nonce          users.nonce%TYPE;
        v_key            users.key%TYPE;
        v_secret         users.secret%TYPE;
        v_pos number(9);
    v_api_sign          VARCHAR2(88);
    BEGIN
        SELECT key, secret
        INTO v_key, v_secret
        FROM users
        WHERE id = 1;

        v_hmac_request := ws_authentication.hmac('sessions', 'active', 'serial=27148', v_secret);
        v_pos := instr(v_hmac_request.post_data,'=',-1)+1;
        v_nonce := substr(v_hmac_request.post_data, v_pos);
        v_api_sign := v_hmac_request.api_sign;
        v_user_ok := ws_authentication.check_hmac('sessions', 'active', 'serial=27148', v_nonce, v_key, v_api_sign);

        IF v_user_ok = true THEN
            dbms_output.put_line('User OK');
        ELSE
            dbms_output.put_line('Wrong user credentials');
        END IF;

    END check_hmac;

    PROCEDURE generate_secret IS
        v_secret VARCHAR2(2048);
    BEGIN
        v_secret := ws_authentication.generate_secret;
        dbms_output.put_line(v_secret);
    END generate_secret;

END test_ws_authentication;
