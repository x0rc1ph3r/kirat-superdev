use poem::{
    Route, Server, get, handler,
    listener::TcpListener,
    post,
    web::{Json},
    Result as PoemResult,
};
use poem::endpoint::EndpointExt;
use poem::http::StatusCode;
use poem::Response;
use solana_sdk::{
    signature::{Keypair, Signer, Signature},
    instruction::{AccountMeta, Instruction},
    system_instruction,
    pubkey::Pubkey as SolanaPubkey,
};
use spl_token::{
    instruction as token_instruction, 
    ID as TOKEN_PROGRAM_ID,
};
use spl_associated_token_account;
use base58::{ToBase58, FromBase58};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use tracing::{info, error};
use tracing_subscriber;

#[derive(Serialize, Deserialize)]
pub struct KeypairResponse {
    pub pubkey: String,
    pub secret: String,
}

#[derive(Serialize, Deserialize)]
pub struct CreateTokenRequest {
    pub mintAuthority: String,
    pub mint: String,
    pub decimals: u8,
}

#[derive(Serialize, Deserialize)]
pub struct MintTokenRequest {
    pub mint: String,
    pub destination: String,
    pub authority: String,
    pub amount: u64,
}

#[derive(Serialize, Deserialize)]
pub struct SignMessageRequest {
    pub message: String,
    pub secret: String,
}

#[derive(Serialize, Deserialize)]
pub struct VerifyMessageRequest {
    pub message: String,
    pub signature: String,
    pub pubkey: String,
}

#[derive(Serialize, Deserialize)]
pub struct SendSolRequest {
    pub from: String,
    pub to: String,
    pub lamports: u64,
}

#[derive(Serialize, Deserialize)]
pub struct SendTokenRequest {
    pub destination: String,
    pub mint: String,
    pub owner: String,
    pub amount: u64,
}

#[derive(Serialize, Deserialize)]
pub struct SignMessageResponse {
    pub signature: String,
    pub public_key: String,
    pub message: String,
}

#[derive(Serialize, Deserialize)]
pub struct VerifyMessageResponse {
    pub valid: bool,
    pub message: String,
    pub pubkey: String,
}

#[derive(Serialize, Deserialize)]
pub struct TransferResponse {
    pub program_id: String,
    pub accounts: Vec<AccountMetaResponse>,
    pub instruction_data: String,
}

#[derive(Serialize, Deserialize)]
pub struct AccountMetaResponse {
    pub pubkey: String,
    pub is_signer: bool,
    pub is_writable: bool,
}

#[derive(Serialize, Deserialize)]
pub struct TokenCreateResponse {
    pub program_id: String,
    pub accounts: Vec<AccountMetaResponse>,
    pub instruction_data: String,
}

#[derive(Serialize, Deserialize)]
pub struct TokenMintResponse {
    pub program_id: String,
    pub accounts: Vec<AccountMetaResponse>,
    pub instruction_data: String,
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum ApiResponse {
    Success { success: bool, data: KeypairResponse },
    TokenSuccess { success: bool, data: TokenCreateResponse },
    TokenMintSuccess { success: bool, data: TokenMintResponse },
    SignMessageSuccess { success: bool, data: SignMessageResponse },
    VerifyMessageSuccess { success: bool, data: VerifyMessageResponse },
    TransferSuccess { success: bool, data: TransferResponse },
    Error { success: bool, error: String },
}

fn success_response<T: Serialize>(data: T) -> Response {
    let body = serde_json::to_string(&data)
        .unwrap_or_else(|_| "{\"success\":false,\"error\":\"Internal serialization error\"}".to_string());
    Response::builder()
        .status(StatusCode::OK)
        .body(body)
}


fn error_response(message: &str) -> Response {
    let body = serde_json::to_string(&ApiResponse::Error {
        success: false,
        error: message.to_string(),
    }).unwrap_or_else(|_| "{\"success\":false,\"error\":\"Internal serialization error\"}".to_string());

    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(body)
}

#[handler]
fn generate_keypair() -> PoemResult<Response> {
    match std::panic::catch_unwind(|| {
        let keypair = Keypair::new();
        let secret_bytes = keypair.to_bytes();
        let response = KeypairResponse {
            pubkey: keypair.pubkey().to_string(),
            secret: secret_bytes.to_base58(),
        };
        success_response(ApiResponse::Success {
            success: true,
            data: response,
        })
    }) {
        Ok(resp) => Ok(resp),
        Err(_) => Ok(error_response("Failed to create keypair")),
    }
}

#[handler]
fn create_token(Json(payload): Json<CreateTokenRequest>) -> PoemResult<Response> {
    info!("Creating token: mint = {}, authority = {}", payload.mint, payload.mintAuthority);
    match std::panic::catch_unwind(|| {
        let mint_authority = match SolanaPubkey::from_str(&payload.mintAuthority) {
            Ok(pubkey) => pubkey,
            Err(_) => return error_response("Invalid mint authority pubkey"),
        };
        let mint = match SolanaPubkey::from_str(&payload.mint) {
            Ok(pubkey) => pubkey,
            Err(_) => return error_response("Invalid mint pubkey"),
        };
        let instruction = match token_instruction::initialize_mint(
            &TOKEN_PROGRAM_ID,
            &mint,
            &mint_authority,
            None,
            payload.decimals,
        ) {
            Ok(instr) => instr,
            Err(_) => return error_response("Failed to create token instruction"),
        };
        let accounts: Vec<AccountMetaResponse> = instruction.accounts.iter().map(|account| {
            AccountMetaResponse {
                pubkey: account.pubkey.to_string(),
                is_signer: account.is_signer,
                is_writable: account.is_writable,
            }
        }).collect();
        let instruction_data = base64::encode(&instruction.data);
        success_response(ApiResponse::TokenSuccess {
            success: true,
            data: TokenCreateResponse {
                program_id: instruction.program_id.to_string(),
                accounts,
                instruction_data,
            },
        })
    }) {
        Ok(resp) => Ok(resp),
        Err(_) => Ok(error_response("Failed to create token instruction")),
    }
}

#[handler]
fn mint_token(Json(payload): Json<MintTokenRequest>) -> PoemResult<Response> {
    match std::panic::catch_unwind(|| {
        let mint = match SolanaPubkey::from_str(&payload.mint) {
            Ok(pubkey) => pubkey,
            Err(_) => return error_response("Invalid mint pubkey"),
        };
        let destination = match SolanaPubkey::from_str(&payload.destination) {
            Ok(pubkey) => pubkey,
            Err(_) => return error_response("Invalid destination pubkey"),
        };
        let authority = match SolanaPubkey::from_str(&payload.authority) {
            Ok(pubkey) => pubkey,
            Err(_) => return error_response("Invalid authority pubkey"),
        };
        let instruction = match token_instruction::mint_to(
            &TOKEN_PROGRAM_ID,
            &mint,
            &destination,
            &authority,
            &[],
            payload.amount,
        ) {
            Ok(instr) => instr,
            Err(_) => return error_response("Failed to create mint token instruction"),
        };
        let accounts: Vec<AccountMetaResponse> = instruction.accounts.iter().map(|account| {
            AccountMetaResponse {
                pubkey: account.pubkey.to_string(),
                is_signer: account.is_signer,
                is_writable: account.is_writable,
            }
        }).collect();
        let instruction_data = base64::encode(&instruction.data);
        success_response(ApiResponse::TokenMintSuccess {
            success: true,
            data: TokenMintResponse {
                program_id: instruction.program_id.to_string(),
                accounts,
                instruction_data,
            },
        })
    }) {
        Ok(resp) => Ok(resp),
        Err(_) => Ok(error_response("Failed to create mint token instruction")),
    }
}

fn check_missing_fields(fields: &[(&str, &str)]) -> Option<Response> {
    for (name, value) in fields {
        if value.trim().is_empty() {
            return Some(error_response("Missing required fields"));
        }
    }
    None
}

#[handler]
fn sign_message(Json(payload): Json<SignMessageRequest>) -> PoemResult<Response> {
    if let Some(resp) = check_missing_fields(&[
        ("message", &payload.message),
        ("secret", &payload.secret),
    ]) {
        return Ok(resp);
    }
    match std::panic::catch_unwind(|| {
        let secret_bytes = match payload.secret.from_base58() {
            Ok(bytes) => bytes,
            Err(_) => return error_response("Invalid base58 secret key"),
        };
        if secret_bytes.len() != 64 {
            return error_response("Invalid secret key length");
        }
        let keypair = match Keypair::from_bytes(&secret_bytes) {
            Ok(kp) => kp,
            Err(_) => return error_response("Failed to create keypair from secret"),
        };
        let message_bytes = payload.message.as_bytes();
        let signature = keypair.sign_message(message_bytes);
        success_response(ApiResponse::SignMessageSuccess {
            success: true,
            data: SignMessageResponse {
                signature: base64::encode(signature.as_ref()),
                public_key: keypair.pubkey().to_string(),
                message: payload.message,
            },
        })
    }) {
        Ok(resp) => Ok(resp),
        Err(_) => Ok(error_response("Failed to sign message")),
    }
}

#[handler]
fn verify_message(Json(payload): Json<VerifyMessageRequest>) -> PoemResult<Response> {
    if let Some(resp) = check_missing_fields(&[
        ("message", &payload.message),
        ("signature", &payload.signature),
        ("pubkey", &payload.pubkey),
    ]) {
        return Ok(resp);
    }

    match std::panic::catch_unwind(|| {
        let pubkey = match SolanaPubkey::from_str(&payload.pubkey) {
            Ok(pk) => pk,
            Err(_) => return error_response("Invalid public key"),
        };

        let signature_bytes = match base64::decode(&payload.signature) {
            Ok(bytes) => bytes,
            Err(_) => return error_response("Invalid base64 signature"),
        };

        let signature = match Signature::try_from(signature_bytes.as_slice()) {
            Ok(sig) => sig,
            Err(_) => return error_response("Invalid signature format"),
        };

        let message_bytes = payload.message.as_bytes();
        let is_valid = signature.verify(&pubkey.as_ref(), message_bytes);

        success_response(ApiResponse::VerifyMessageSuccess {
            success: true,
            data: VerifyMessageResponse {
                valid: is_valid,
                message: payload.message,
                pubkey: payload.pubkey,
            },
        })
    }) {
        Ok(resp) => Ok(resp),
        Err(_) => Ok(error_response("Failed to verify message")),
    }
}

#[handler]
fn send_sol(Json(payload): Json<SendSolRequest>) -> PoemResult<Response> {
    if let Some(resp) = check_missing_fields(&[
        ("from", &payload.from),
        ("to", &payload.to),
    ]) {
        return Ok(resp);
    }
    if payload.lamports == 0 {
        return Ok(error_response("Invalid amount"));
    }

    match std::panic::catch_unwind(|| {
        let from_pubkey = match SolanaPubkey::from_str(&payload.from) {
            Ok(pk) => pk,
            Err(_) => return error_response("Invalid from address"),
        };

        let to_pubkey = match SolanaPubkey::from_str(&payload.to) {
            Ok(pk) => pk,
            Err(_) => return error_response("Invalid to address"),
        };

        let instruction = system_instruction::transfer(&from_pubkey, &to_pubkey, payload.lamports);

        let accounts: Vec<AccountMetaResponse> = instruction.accounts.iter().map(|account| {
            AccountMetaResponse {
                pubkey: account.pubkey.to_string(),
                is_signer: account.is_signer,
                is_writable: account.is_writable,
            }
        }).collect();

        let instruction_data = base64::encode(&instruction.data);

        success_response(ApiResponse::TransferSuccess {
            success: true,
            data: TransferResponse {
                program_id: instruction.program_id.to_string(),
                accounts,
                instruction_data,
            },
        })
    }) {
        Ok(resp) => Ok(resp),
        Err(_) => Ok(error_response("Failed to create SOL transfer instruction")),
    }
}

#[handler]
fn send_token(Json(payload): Json<SendTokenRequest>) -> PoemResult<Response> {
    if let Some(resp) = check_missing_fields(&[
        ("destination", &payload.destination),
        ("mint", &payload.mint),
        ("owner", &payload.owner),
    ]) {
        return Ok(resp);
    }
    if payload.amount == 0 {
        return Ok(error_response("Invalid amount"));
    }

    match std::panic::catch_unwind(|| {
        let mint = match SolanaPubkey::from_str(&payload.mint) {
            Ok(pk) => pk,
            Err(_) => return error_response("Invalid mint address"),
        };

        let owner = match SolanaPubkey::from_str(&payload.owner) {
            Ok(pk) => pk,
            Err(_) => return error_response("Invalid owner address"),
        };

        let destination = match SolanaPubkey::from_str(&payload.destination) {
            Ok(pk) => pk,
            Err(_) => return error_response("Invalid destination address"),
        };

        let source_ata = spl_associated_token_account::get_associated_token_address(&owner, &mint);
        let destination_ata = spl_associated_token_account::get_associated_token_address(&destination, &mint);

        let instruction = match token_instruction::transfer(
            &TOKEN_PROGRAM_ID,
            &source_ata,
            &destination_ata,
            &owner,
            &[],
            payload.amount,
        ) {
            Ok(instr) => instr,
            Err(_) => return error_response("Failed to create token transfer instruction"),
        };

        let accounts: Vec<AccountMetaResponse> = instruction.accounts.iter().map(|account| {
            AccountMetaResponse {
                pubkey: account.pubkey.to_string(),
                is_signer: account.is_signer,
                is_writable: account.is_writable,
            }
        }).collect();

        let instruction_data = base64::encode(&instruction.data);

        success_response(ApiResponse::TransferSuccess {
            success: true,
            data: TransferResponse {
                program_id: instruction.program_id.to_string(),
                accounts,
                instruction_data,
            },
        })
    }) {
        Ok(resp) => Ok(resp),
        Err(_) => Ok(error_response("Failed to create token transfer instruction")),
    }
}

#[handler]
fn home() -> String {
    String::from(
        "server running"
    )
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let app = Route::new()
        .at("/", get(home))
        .at("/keypair", post(generate_keypair))
        .at("/token/create", post(create_token))
        .at("/token/mint", post(mint_token))
        .at("/message/sign", post(sign_message))
        .at("/message/verify", post(verify_message))
        .at("/send/sol", post(send_sol))
        .at("/send/token", post(send_token));

    println!("running at http://0.0.0.0:3000");
    Server::new(TcpListener::bind("0.0.0.0:3000"))
        .name("solana-api")
        .run(app)
        .await
}