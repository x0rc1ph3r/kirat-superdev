use poem::{
    Route, Server, get, handler, post,
    listener::TcpListener,
    web::{Json},
    Error as PoemError,
    Result as PoemResult,
};
use poem::http::StatusCode;
use serde::{Deserialize, Serialize};
use solana_sdk::{
    signature::{Keypair, Signer},
    pubkey::Pubkey as SolanaPubkey,
    instruction::Instruction,
    system_instruction,
};
use spl_token::{instruction as token_instruction, ID as TOKEN_PROGRAM_ID};
use spl_associated_token_account::get_associated_token_address;
use base58::{ToBase58, FromBase58};
use std::str::FromStr;
use std::panic;

/// Standard API response wrapper
#[derive(Serialize)]
enum ApiResponse<T> {
    #[serde(rename = "success")]
    True { success: bool, data: T },
    #[serde(rename = "error")]
    False { success: bool, error: String },
}

// Request/Response struct definitions
#[derive(Deserialize)]
struct CreateTokenRequest { mint_authority: String, mint: String, decimals: u8 }
#[derive(Serialize)]
struct TokenCreateResponse { program_id: String, accounts: Vec<AccountMetaInfo>, instruction_data: String }

#[derive(Deserialize)]
struct MintTokenRequest { mint: String, destination: String, authority: String, amount: u64 }
#[derive(Serialize)]
struct TokenMintResponse { program_id: String, accounts: Vec<AccountMetaInfo>, instruction_data: String }

#[derive(Deserialize)]
struct SignMessageRequest { message: String, secret: String }
#[derive(Serialize)]
struct SignMessageResponse { signature: String, public_key: String, message: String }

#[derive(Deserialize)]
struct VerifyMessageRequest { message: String, signature: String, pubkey: String }
#[derive(Serialize)]
struct VerifyMessageResponse { valid: bool, message: String, pubkey: String }

#[derive(Deserialize)]
struct SendSolRequest { from: String, to: String, lamports: u64 }

#[derive(Deserialize)]
struct SendTokenRequest { owner: String, destination: String, mint: String, amount: u64 }

#[derive(Serialize)]
struct TransferResponse { program_id: String, accounts: Vec<AccountMetaInfo>, instruction_data: String }

#[derive(Serialize)]
struct AccountMetaInfo { pubkey: String, is_signer: bool, is_writable: bool }

#[derive(Serialize)]
struct KeypairResponse { secret: String, public_key: String }

// Helper for error return
fn bad_request(msg: &str) -> PoemError {
    PoemError::from_string(msg.to_string(), StatusCode::BAD_REQUEST)
}

// Handlers
#[handler]
async fn home() -> &'static str {
    "Solana API is up and running!"
}

#[handler]
fn generate_keypair() -> PoemResult<Json<ApiResponse<KeypairResponse>>> {
    let keypair = Keypair::new();
    let secret = keypair.to_bytes().to_base58();
    let public_key = keypair.pubkey().to_string();
    Ok(Json(ApiResponse::True { success: true, data: KeypairResponse { secret, public_key } }))
}

#[handler]
fn create_token(Json(payload): Json<CreateTokenRequest>) -> PoemResult<Json<ApiResponse<TokenCreateResponse>>> {
    // parse and validate
    let mint_authority = SolanaPubkey::from_str(&payload.mint_authority)
        .map_err(|_| bad_request("Invalid mint authority pubkey"))?;
    let mint = SolanaPubkey::from_str(&payload.mint)
        .map_err(|_| bad_request("Invalid mint pubkey"))?;
    // build instruction
    let instruction = token_instruction::initialize_mint(
        &TOKEN_PROGRAM_ID,
        &mint,
        &mint_authority,
        None,
        payload.decimals,
    ).map_err(|_| bad_request("Failed to create token instruction"))?;
    // respond
    let accounts = instruction.accounts.iter().map(|a| AccountMetaInfo {
        pubkey: a.pubkey.to_string(), is_signer: a.is_signer, is_writable: a.is_writable
    }).collect();
    let instruction_data = base64::encode(&instruction.data);
    Ok(Json(ApiResponse::True { success: true, data: TokenCreateResponse {
        program_id: instruction.program_id.to_string(), accounts, instruction_data
    }}))
}

#[handler]
fn mint_token(Json(payload): Json<MintTokenRequest>) -> PoemResult<Json<ApiResponse<TokenMintResponse>>> {
    let mint = SolanaPubkey::from_str(&payload.mint)
        .map_err(|_| bad_request("Invalid mint pubkey"))?;
    let destination = SolanaPubkey::from_str(&payload.destination)
        .map_err(|_| bad_request("Invalid destination pubkey"))?;
    let authority = SolanaPubkey::from_str(&payload.authority)
        .map_err(|_| bad_request("Invalid authority pubkey"))?;
    let instruction = token_instruction::mint_to(
        &TOKEN_PROGRAM_ID,
        &mint,
        &destination,
        &authority,
        &[],
        payload.amount,
    ).map_err(|_| bad_request("Failed to create mint token instruction"))?;
    let accounts = instruction.accounts.iter().map(|a| AccountMetaInfo {
        pubkey: a.pubkey.to_string(), is_signer: a.is_signer, is_writable: a.is_writable
    }).collect();
    let instruction_data = base64::encode(&instruction.data);
    Ok(Json(ApiResponse::True { success: true, data: TokenMintResponse {
        program_id: instruction.program_id.to_string(), accounts, instruction_data
    }}))
}

#[handler]
fn sign_message(Json(payload): Json<SignMessageRequest>) -> PoemResult<Json<ApiResponse<SignMessageResponse>>> {
    if payload.message.is_empty() || payload.secret.is_empty() {
        return Err(bad_request("Missing required fields"));
    }
    let secret_bytes = payload.secret.from_base58()
        .map_err(|_| bad_request("Invalid base58 secret key"))?;
    if secret_bytes.len() != 64 {
        return Err(bad_request("Invalid secret key length"));
    }
    let keypair = Keypair::from_bytes(&secret_bytes)
        .map_err(|_| bad_request("Failed to create keypair from secret"))?;
    let sig = keypair.sign_message(payload.message.as_bytes());
    Ok(Json(ApiResponse::True { success: true, data: SignMessageResponse {
        signature: base64::encode(sig.as_ref()),
        public_key: keypair.pubkey().to_string(),
        message: payload.message,
    }}))
}

#[handler]
fn verify_message(Json(payload): Json<VerifyMessageRequest>) -> PoemResult<Json<ApiResponse<VerifyMessageResponse>>> {
    if payload.message.is_empty() || payload.signature.is_empty() || payload.pubkey.is_empty() {
        return Err(bad_request("Missing required fields"));
    }
    let pubkey = SolanaPubkey::from_str(&payload.pubkey)
        .map_err(|_| bad_request("Invalid public key"))?;
    let sig_bytes = base64::decode(&payload.signature)
        .map_err(|_| bad_request("Invalid base64 signature"))?;
    let signature = solana_sdk::signature::Signature::try_from(sig_bytes.as_slice())
        .map_err(|_| bad_request("Invalid signature format"))?;
    let valid = signature.verify(&pubkey.as_ref(), payload.message.as_bytes());
    Ok(Json(ApiResponse::True { success: true, data: VerifyMessageResponse {
        valid, message: payload.message, pubkey: payload.pubkey,
    }}))
}

#[handler]
fn send_sol(Json(payload): Json<SendSolRequest>) -> PoemResult<Json<ApiResponse<TransferResponse>>> {
    if payload.from.is_empty() || payload.to.is_empty() || payload.lamports == 0 {
        return Err(bad_request("Missing required fields or invalid amount"));
    }
    let from_pk = SolanaPubkey::from_str(&payload.from)
        .map_err(|_| bad_request("Invalid from address"))?;
    let to_pk = SolanaPubkey::from_str(&payload.to)
        .map_err(|_| bad_request("Invalid to address"))?;
    let instruction: Instruction = system_instruction::transfer(&from_pk, &to_pk, payload.lamports);
    let accounts = instruction.accounts.iter().map(|a| AccountMetaInfo {
        pubkey: a.pubkey.to_string(), is_signer: a.is_signer, is_writable: a.is_writable
    }).collect();
    Ok(Json(ApiResponse::True { success: true, data: TransferResponse {
        program_id: instruction.program_id.to_string(), accounts, instruction_data: base64::encode(&instruction.data)
    }}))
}

#[handler]
fn send_token(Json(payload): Json<SendTokenRequest>) -> PoemResult<Json<ApiResponse<TransferResponse>>> {
    if payload.owner.is_empty() || payload.destination.is_empty() || payload.mint.is_empty() || payload.amount == 0 {
        return Err(bad_request("Missing required fields or invalid amount"));
    }
    let mint = SolanaPubkey::from_str(&payload.mint)
        .map_err(|_| bad_request("Invalid mint address"))?;
    let owner = SolanaPubkey::from_str(&payload.owner)
        .map_err(|_| bad_request("Invalid owner address"))?;
    let destination = SolanaPubkey::from_str(&payload.destination)
        .map_err(|_| bad_request("Invalid destination address"))?;
    let source_ata = get_associated_token_address(&owner, &mint);
    let dest_ata = get_associated_token_address(&destination, &mint);
    let instruction = token_instruction::transfer(
        &TOKEN_PROGRAM_ID,
        &source_ata,
        &dest_ata,
        &owner,
        &[],
        payload.amount,
    ).map_err(|_| bad_request("Failed to create token transfer instruction"))?;
    let accounts = instruction.accounts.iter().map(|a| AccountMetaInfo {
        pubkey: a.pubkey.to_string(), is_signer: a.is_signer, is_writable: a.is_writable
    }).collect();
    Ok(Json(ApiResponse::True { success: true, data: TransferResponse {
        program_id: instruction.program_id.to_string(), accounts, instruction_data: base64::encode(&instruction.data)
    }}))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let app = Route::new()
        .at("/", get(home))
        .at("/keypair", post(generate_keypair))
        .at("/token/create", post(create_token))
        .at("/token/mint", post(mint_token))
        .at("/message/sign", post(sign_message))
        .at("/message/verify", post(verify_message))
        .at("/send/sol", post(send_sol))
        .at("/send/token", post(send_token));

    println!("Server running at http://0.0.0.0:3000");
    Server::new(TcpListener::bind("0.0.0.0:3000")).run(app).await?;
    Ok(())
}
