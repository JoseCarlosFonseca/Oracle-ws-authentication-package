@ws_authentication.sql
@ws_authentication_body.sql
@test_ws_authentication.sql
@test_ws_authentication_body.sql

DROP TABLE users;

CREATE TABLE users (
    id              NUMBER(9) GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username        VARCHAR2(20) UNIQUE,
    key             VARCHAR2(56) UNIQUE,
    secret          VARCHAR2(88),
    creation_date   NUMBER(16),
    nonce           NUMBER(16)
);

declare
v_id users.id%TYPE;
begin
v_id := ws_authentication.create_user('Jose');
end;
/

COMMIT;

set serveroutput on;

exec test_ws_authentication.basic;
exec test_ws_authentication.from_base64;
exec test_ws_authentication.generate_secret;
exec test_ws_authentication.hmac;
exec test_ws_authentication.check_hmac;
