use poem::{
    Route, Server, get, handler, post,
    listener::TcpListener,
    web::{Json},
    Result as PoemResult,
};
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
    match panic::catch_unwind(|| -> PoemResult<Json<ApiResponse<TokenCreateResponse>>> {
        let mint_authority = match SolanaPubkey::from_str(&payload.mint_authority) {
            Ok(pk) => pk,
            Err(_) => return Ok(Json(ApiResponse::False { success: false, error: "Invalid mint authority pubkey".to_string() })),
        };
        let mint = match SolanaPubkey::from_str(&payload.mint) {
            Ok(pk) => pk,
            Err(_) => return Ok(Json(ApiResponse::False { success: false, error: "Invalid mint pubkey".to_string() })),
        };
        let instruction = match token_instruction::initialize_mint(
            &TOKEN_PROGRAM_ID,
            &mint,
            &mint_authority,
            None,
            payload.decimals,
        ) {
            Ok(ix) => ix,
            Err(_) => return Ok(Json(ApiResponse::False { success: false, error: "Failed to create token instruction".to_string() })),
        };
        let accounts = instruction.accounts.iter().map(|account| AccountMetaInfo {
            pubkey: account.pubkey.to_string(), is_signer: account.is_signer, is_writable: account.is_writable
        }).collect();
        let instruction_data = base64::encode(&instruction.data);
        Ok(Json(ApiResponse::True { success: true, data: TokenCreateResponse {
            program_id: instruction.program_id.to_string(), accounts, instruction_data
        }}))
    }) {
        Ok(res) => res,
        Err(_) => Ok(Json(ApiResponse::False { success: false, error: "Failed to create token instruction".to_string() })),
    }
}

#[handler]
fn mint_token(Json(payload): Json<MintTokenRequest>) -> PoemResult<Json<ApiResponse<TokenMintResponse>>> {
    match panic::catch_unwind(|| -> PoemResult<Json<ApiResponse<TokenMintResponse>>> {
        let mint = match SolanaPubkey::from_str(&payload.mint) {
            Ok(pk) => pk,
            Err(_) => return Ok(Json(ApiResponse::False { success: false, error: "Invalid mint pubkey".to_string() })),
        };
        let destination = match SolanaPubkey::from_str(&payload.destination) {
            Ok(pk) => pk,
            Err(_) => return Ok(Json(ApiResponse::False { success: false, error: "Invalid destination pubkey".to_string() })),
        };
        let authority = match SolanaPubkey::from_str(&payload.authority) {
            Ok(pk) => pk,
            Err(_) => return Ok(Json(ApiResponse::False { success: false, error: "Invalid authority pubkey".to_string() })),
        };
        let instruction = match token_instruction::mint_to(
            &TOKEN_PROGRAM_ID,
            &mint,
            &destination,
            &authority,
            &[],
            payload.amount,
        ) {
            Ok(ix) => ix,
            Err(_) => return Ok(Json(ApiResponse::False { success: false, error: "Failed to create mint token instruction".to_string() })),
        };
        let accounts = instruction.accounts.iter().map(|account| AccountMetaInfo {
            pubkey: account.pubkey.to_string(), is_signer: account.is_signer, is_writable: account.is_writable
        }).collect();
        let instruction_data = base64::encode(&instruction.data);
        Ok(Json(ApiResponse::True { success: true, data: TokenMintResponse {
            program_id: instruction.program_id.to_string(), accounts, instruction_data
        }}))
    }) {
        Ok(res) => res,
        Err(_) => Ok(Json(ApiResponse::False { success: false, error: "Failed to create mint token instruction".to_string() })),
    }
}

#[handler]
fn sign_message(Json(payload): Json<SignMessageRequest>) -> PoemResult<Json<ApiResponse<SignMessageResponse>>> {
    if payload.message.is_empty() || payload.secret.is_empty() {
        return Ok(Json(ApiResponse::False { success: false, error: "Missing required fields".to_string() }));
    }
    match panic::catch_unwind(|| -> PoemResult<Json<ApiResponse<SignMessageResponse>>> {
        let secret_bytes = match payload.secret.from_base58() {
            Ok(b) => b,
            Err(_) => return Ok(Json(ApiResponse::False { success: false, error: "Invalid base58 secret key".to_string() })),
        };
        if secret_bytes.len() != 64 {
            return Ok(Json(ApiResponse::False { success: false, error: "Invalid secret key length".to_string() }));
        }
        let keypair = match Keypair::from_bytes(&secret_bytes) {
            Ok(kp) => kp,
            Err(_) => return Ok(Json(ApiResponse::False { success: false, error: "Failed to create keypair from secret".to_string() })),
        };
        let sig = keypair.sign_message(payload.message.as_bytes());
        Ok(Json(ApiResponse::True { success: true, data: SignMessageResponse {
            signature: base64::encode(sig.as_ref()), public_key: keypair.pubkey().to_string(), message: payload.message
        }}))
    }) {
        Ok(res) => res,
        Err(_) => Ok(Json(ApiResponse::False { success: false, error: "Failed to sign message".to_string() })),
    }
}

#[handler]
fn verify_message(Json(payload): Json<VerifyMessageRequest>) -> PoemResult<Json<ApiResponse<VerifyMessageResponse>>> {
    if payload.message.is_empty() || payload.signature.is_empty() || payload.pubkey.is_empty() {
        return Ok(Json(ApiResponse::False { success: false, error: "Missing required fields".to_string() }));
    }
    match panic::catch_unwind(|| -> PoemResult<Json<ApiResponse<VerifyMessageResponse>>> {
        let pubkey = match SolanaPubkey::from_str(&payload.pubkey) {
            Ok(pk) => pk,
            Err(_) => return Ok(Json(ApiResponse::False { success: false, error: "Invalid public key".to_string() })),
        };
        let sig_bytes = match base64::decode(&payload.signature) {
            Ok(b) => b,
            Err(_) => return Ok(Json(ApiResponse::False { success: false, error: "Invalid base64 signature".to_string() })),
        };
        let signature = match solana_sdk::signature::Signature::try_from(sig_bytes.as_slice()) {
            Ok(s) => s,
            Err(_) => return Ok(Json(ApiResponse::False { success: false, error: "Invalid signature format".to_string() })),
        };
        let is_valid = signature.verify(&pubkey.as_ref(), payload.message.as_bytes());
        Ok(Json(ApiResponse::True { success: true, data: VerifyMessageResponse {
            valid: is_valid, message: payload.message, pubkey: payload.pubkey
        }}))
    }) {
        Ok(res) => res,
        Err(_) => Ok(Json(ApiResponse::False { success: false, error: "Failed to verify message".to_string() })),
    }
}

#[handler]
fn send_sol(Json(payload): Json<SendSolRequest>) -> PoemResult<Json<ApiResponse<TransferResponse>>> {
    if payload.from.is_empty() || payload.to.is_empty() || payload.lamports == 0 {
        return Ok(Json(ApiResponse::False { success: false, error: "Missing required fields or invalid amount".to_string() }));
    }
    match panic::catch_unwind(|| -> PoemResult<Json<ApiResponse<TransferResponse>>> {
        let from_pk = match SolanaPubkey::from_str(&payload.from) {
            Ok(pk) => pk,
            Err(_) => return Ok(Json(ApiResponse::False { success: false, error: "Invalid from address".to_string() })),
        };
        let to_pk = match SolanaPubkey::from_str(&payload.to) {
            Ok(pk) => pk,
            Err(_) => return Ok(Json(ApiResponse::False { success: false, error: "Invalid to address".to_string() })),
        };
        let instruction: Instruction = system_instruction::transfer(&from_pk, &to_pk, payload.lamports);
        let accounts = instruction.accounts.iter().map(|account| AccountMetaInfo {
            pubkey: account.pubkey.to_string(), is_signer: account.is_signer, is_writable: account.is_writable
        }).collect();
        Ok(Json(ApiResponse::True { success: true, data: TransferResponse {
            program_id: instruction.program_id.to_string(), accounts, instruction_data: base64::encode(&instruction.data)
        }}))
    }) {
        Ok(res) => res,
        Err(_) => Ok(Json(ApiResponse::False { success: false, error: "Failed to create SOL transfer instruction".to_string() })),
    }
}

#[handler]
fn send_token(Json(payload): Json<SendTokenRequest>) -> PoemResult<Json<ApiResponse<TransferResponse>>> {
    if payload.owner.is_empty() || payload.destination.is_empty() || payload.mint.is_empty() || payload.amount == 0 {
        return Ok(Json(ApiResponse::False { success: false, error: "Missing required fields or invalid amount".to_string() }));
    }
    match panic::catch_unwind(|| -> PoemResult<Json<ApiResponse<TransferResponse>>> {
        let mint = match SolanaPubkey::from_str(&payload.mint) {
            Ok(pk) => pk,
            Err(_) => return Ok(Json(ApiResponse::False { success: false, error: "Invalid mint address".to_string() })),
        };
        let owner = match SolanaPubkey::from_str(&payload.owner) {
            Ok(pk) => pk,
            Err(_) => return Ok(Json(ApiResponse::False { success: false, error: "Invalid owner address".to_string() })),
        };
        let destination = match SolanaPubkey::from_str(&payload.destination) {
            Ok(pk) => pk,
            Err(_) => return Ok(Json(ApiResponse::False { success: false, error: "Invalid destination address".to_string() })),
        };
        let source_ata = get_associated_token_address(&owner, &mint);
        let dest_ata = get_associated_token_address(&destination, &mint);
        let instruction = match token_instruction::transfer(
            &TOKEN_PROGRAM_ID,
            &source_ata,
            &dest_ata,
            &owner,
            &[],
            payload.amount,
        ) {
            Ok(ix) => ix,
            Err(_) => return Ok(Json(ApiResponse::False { success: false, error: "Failed to create token transfer instruction".to_string() })),
        };
        let accounts = instruction.accounts.iter().map(|account| AccountMetaInfo {
            pubkey: account.pubkey.to_string(), is_signer: account.is_signer, is_writable: account.is_writable
        }).collect();
        Ok(Json(ApiResponse::True { success: true, data: TransferResponse {
            program_id: instruction.program_id.to_string(), accounts, instruction_data: base64::encode(&instruction.data)
        }}))
    }) {
        Ok(res) => res,
        Err(_) => Ok(Json(ApiResponse::False { success: false, error: "Failed to create token transfer instruction".to_string() })),
    }
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
