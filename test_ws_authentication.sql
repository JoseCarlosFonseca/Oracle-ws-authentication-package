create or replace PACKAGE test_ws_authentication IS
    PROCEDURE basic;

    PROCEDURE from_base64;

    PROCEDURE hmac;

    PROCEDURE check_hmac;

    PROCEDURE generate_secret;

END test_ws_authentication;
