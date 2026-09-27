-- FrostyFriday課題ページ：https://www.frostyfri.day/en/challenges/blog/2024/10/25/week-116-security-governance
-- 参考1: https://www.snowflake.com/ja/blog/blocking-single-factor-password-authentification/
-- 参考2: https://www.snowflake.com/ja/resources/white-paper/best-practices-to-mitigate-the-risk-of-credential-compromise/

-- ※2026年9月末現在、新規のhumanユーザーはすでにMFA必須となっており、既存も含めた全humanユーザーへのMFA必須化が2026年10月までに順次適用されています。
-- https://docs.snowflake.com/ja/user-guide/security-mfa-rollout

-- ========================================
-- 環境セット：認証ポリシーの配置先となるDB/スキーマを用意し、検証用のユーザー（Alicia / Marco / サービスユーザー）を作成。
-- ========================================
USE ROLE ACCOUNTADMIN;

CREATE DATABASE IF NOT EXISTS FROSTY_FRIDAY;
CREATE SCHEMA IF NOT EXISTS FROSTY_FRIDAY.WEEK_116;

-- 参考：https://docs.snowflake.com/ja/sql-reference/sql/create-user
CREATE USER IF NOT EXISTS alicia TYPE = PERSON;
CREATE USER IF NOT EXISTS marco  TYPE = PERSON;
-- 追加シナリオ用のサービスユーザー（ETL等のプログラム接続用）
CREATE USER IF NOT EXISTS etl_service_user TYPE = SERVICE;


-- ========================================
-- Step 1：MFA必須の認証ポリシーを作成
-- ========================================
-- 参考：https://docs.snowflake.com/ja/sql-reference/sql/create-authentication-policy
CREATE OR REPLACE AUTHENTICATION POLICY FROSTY_FRIDAY.WEEK_116.enhanced_auth_policy
  MFA_ENROLLMENT = REQUIRED
  COMMENT = 'MFA enforced';

SHOW AUTHENTICATION POLICIES IN SCHEMA FROSTY_FRIDAY.WEEK_116;
DESCRIBE AUTHENTICATION POLICY FROSTY_FRIDAY.WEEK_116.enhanced_auth_policy;


-- ========================================
-- Step 2：「Step 1」の認証ポリシーをアカウント全体に設定
-- ========================================
ALTER ACCOUNT SET AUTHENTICATION POLICY FROSTY_FRIDAY.WEEK_116.enhanced_auth_policy;

SHOW AUTHENTICATION POLICIES ON ACCOUNT;


-- ========================================
-- Step 3：特定ユーザー向けの厳格なポリシー（Snowsightのみ、パスワード+MFAのみ）を作成し、Alicia に設定
-- ※FrostyFridayのシナリオを変更
-- ========================================
CREATE OR REPLACE AUTHENTICATION POLICY FROSTY_FRIDAY.WEEK_116.sensitive_user_auth_policy
  MFA_ENROLLMENT = REQUIRED
  CLIENT_TYPES = ('SNOWFLAKE_UI')
  AUTHENTICATION_METHODS = ('PASSWORD')
  COMMENT = 'MFA enforced, Snowsight only';

DESCRIBE AUTHENTICATION POLICY FROSTY_FRIDAY.WEEK_116.sensitive_user_auth_policy;

-- ユーザー単位の設定はアカウント単位の設定より優先される
ALTER USER alicia SET AUTHENTICATION POLICY FROSTY_FRIDAY.WEEK_116.sensitive_user_auth_policy;

SHOW AUTHENTICATION POLICIES ON USER alicia;


-- ========================================
-- Step 4：policy_manager ロールを作成
-- ========================================
CREATE ROLE IF NOT EXISTS policy_manager;

GRANT APPLY AUTHENTICATION POLICY ON ACCOUNT TO ROLE policy_manager;

-- 検証のため、実行中のユーザーにロールを付与
SET my_user = CURRENT_USER();
GRANT ROLE policy_manager TO USER IDENTIFIER($my_user);

-- policy_manager ロールに付与されている権限を確認
SHOW GRANTS TO ROLE policy_manager;


-- ========================================
-- Step 5：policy_manager で Marco に設定
-- ========================================
USE ROLE policy_manager;

ALTER USER marco SET AUTHENTICATION POLICY FROSTY_FRIDAY.WEEK_116.sensitive_user_auth_policy;

SHOW AUTHENTICATION POLICIES ON USER marco;

-- （参考）ポリシーの作成はできないことを確認（権限エラーになる想定）
CREATE AUTHENTICATION POLICY FROSTY_FRIDAY.WEEK_116.should_fail MFA_ENROLLMENT = REQUIRED;

USE ROLE ACCOUNTADMIN;


-- ========================================
-- Step 6（追加シナリオ）：サービスユーザー用のポリシーを作成し、割り当て
-- ETL等のプログラム接続用ユーザーを、キーペア認証・サービスユーザークライアントからの接続のみに制限。
-- ========================================
CREATE OR REPLACE AUTHENTICATION POLICY FROSTY_FRIDAY.WEEK_116.service_user_auth_policy
  MFA_ENROLLMENT = OPTIONAL
  CLIENT_TYPES = ('DRIVERS', 'SNOWSQL', 'SNOWFLAKE_CLI')
  AUTHENTICATION_METHODS = ('KEYPAIR')
  COMMENT = 'key-pair only for service users';

DESCRIBE AUTHENTICATION POLICY FROSTY_FRIDAY.WEEK_116.service_user_auth_policy;

ALTER USER etl_service_user SET AUTHENTICATION POLICY FROSTY_FRIDAY.WEEK_116.service_user_auth_policy;

SHOW AUTHENTICATION POLICIES ON USER etl_service_user;

-- （任意）キーペアを登録して接続を試す場合
-- 参考：https://docs.snowflake.com/ja/user-guide/key-pair-auth
-- 
--   ローカルで鍵を生成：
--     openssl genrsa 2048 | openssl pkcs8 -topk8 -inform PEM -out rsa_key.p8 -nocrypt
--     openssl rsa -in rsa_key.p8 -pubout -out rsa_key.pub
--   公開鍵（ヘッダー/フッター行を除いた本文）を登録：
-- ALTER USER etl_service_user SET RSA_PUBLIC_KEY = '<公開鍵の本文>';
--   snow CLI 等から rsa_key.p8 で接続できること、Snowsightからはログインできないことを確認


-- ========================================
-- 補足（実行しない）：キーペアの代わりにPAT（Programmatic Access Token）に絞る場合
-- ※デフォルトでは、サービスユーザーがPATを発行/利用するにはネットワークポリシーの適用が必須
-- 参考：https://docs.snowflake.com/ja/user-guide/programmatic-access-tokens
-- ========================================
-- CREATE ROLE IF NOT EXISTS etl_role;
-- GRANT ROLE etl_role TO USER etl_service_user;
--
-- -- ネットワークポリシーの作成
-- CREATE NETWORK POLICY IF NOT EXISTS etl_service_network_policy
--   ALLOWED_IP_LIST = ('<接続元のIP>');
-- ALTER USER etl_service_user SET NETWORK_POLICY = etl_service_network_policy;
--
-- CREATE OR REPLACE AUTHENTICATION POLICY FROSTY_FRIDAY.WEEK_116.service_user_auth_policy
--   MFA_ENROLLMENT = OPTIONAL
--   CLIENT_TYPES = ('DRIVERS', 'SNOWSQL', 'SNOWFLAKE_CLI')
--   AUTHENTICATION_METHODS = ('PROGRAMMATIC_ACCESS_TOKEN')
--   PAT_POLICY = (
--     MAX_EXPIRY_IN_DAYS = 90
--   )
--   COMMENT = 'PAT only for service users';
--
-- ALTER USER etl_service_user SET AUTHENTICATION POLICY FROSTY_FRIDAY.WEEK_116.service_user_auth_policy;
--
-- -- トークン発行
-- ALTER USER etl_service_user ADD PROGRAMMATIC ACCESS TOKEN etl_token
--   ROLE_RESTRICTION = 'ETL_ROLE'
--   DAYS_TO_EXPIRY = 30;
--
-- -- 後片付け
-- ALTER USER etl_service_user REMOVE PROGRAMMATIC ACCESS TOKEN etl_token;
-- ALTER USER etl_service_user UNSET NETWORK_POLICY;
-- DROP NETWORK POLICY IF EXISTS etl_service_network_policy;
-- DROP ROLE IF EXISTS etl_role;


-- ========================================
-- 動作確認（任意）：Alicia / Marco でログインしてMFAが求められるか確認
-- ※新規アカウントではポリシーがなくてもMFAが求められる
-- ========================================
ALTER USER alicia SET PASSWORD = '<パスワード>' MUST_CHANGE_PASSWORD = FALSE;
ALTER USER marco  SET PASSWORD = '<パスワード>' MUST_CHANGE_PASSWORD = FALSE;

-- シークレットウィンドウにてSnowsightを開き、alicia / marco でログインし、
-- パスワード入力後にMFA登録画面が表示されることを確認する
-- SnowSQL等のSnowsight以外のクライアントからはログインが拒否されることも確認できる

-- ログイン結果の確認（要ウェアハウス）
SELECT event_timestamp, user_name, first_authentication_factor,
       second_authentication_factor, is_success, error_message
FROM TABLE(FROSTY_FRIDAY.INFORMATION_SCHEMA.LOGIN_HISTORY_BY_USER(USER_NAME => 'ALICIA'))
ORDER BY event_timestamp DESC;

SELECT event_timestamp, user_name, first_authentication_factor,
       second_authentication_factor, is_success, error_message
FROM TABLE(FROSTY_FRIDAY.INFORMATION_SCHEMA.LOGIN_HISTORY_BY_USER(USER_NAME => 'MARCO'))
ORDER BY event_timestamp DESC;


-- ========================================
-- Step 7（Optional Reset）：ポリシーを外して元の状態に戻す
-- ========================================
ALTER USER alicia UNSET AUTHENTICATION POLICY;
ALTER USER marco  UNSET AUTHENTICATION POLICY;
ALTER USER etl_service_user UNSET AUTHENTICATION POLICY;
ALTER ACCOUNT UNSET AUTHENTICATION POLICY;


-- ========================================
-- 環境クリア
-- ========================================
USE ROLE ACCOUNTADMIN;

ALTER USER IF EXISTS alicia UNSET AUTHENTICATION POLICY;
ALTER USER IF EXISTS marco  UNSET AUTHENTICATION POLICY;
ALTER USER IF EXISTS etl_service_user UNSET AUTHENTICATION POLICY;
ALTER ACCOUNT UNSET AUTHENTICATION POLICY;

DROP AUTHENTICATION POLICY IF EXISTS FROSTY_FRIDAY.WEEK_116.service_user_auth_policy;
DROP AUTHENTICATION POLICY IF EXISTS FROSTY_FRIDAY.WEEK_116.sensitive_user_auth_policy;
DROP AUTHENTICATION POLICY IF EXISTS FROSTY_FRIDAY.WEEK_116.enhanced_auth_policy;
DROP ROLE IF EXISTS policy_manager;
DROP USER IF EXISTS alicia;
DROP USER IF EXISTS marco;
DROP USER IF EXISTS etl_service_user;
DROP SCHEMA IF EXISTS FROSTY_FRIDAY.WEEK_116;
-- DROP DATABASE IF EXISTS FROSTY_FRIDAY;  -- 他のweekでも使うなら実行しない
