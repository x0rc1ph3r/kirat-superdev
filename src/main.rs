use poem::{
    Route, Server, get, handler,
    listener::TcpListener,
    post,
    web::{Json},
    Result as PoemResult,
};

use solana_sdk::{
    signature::{Keypair, Signer},
    instruction::{AccountMeta, Instruction},
};
use spl_token::{
    instruction as token_instruction, solana_program::pubkey::Pubkey, ID as TOKEN_PROGRAM_ID
};
use base58::{ToBase58, FromBase58};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Serialize, Deserialize)]
pub struct KeypairResponse {
    pub pubkey: String,
    pub secret: String,
}

#[derive(Serialize, Deserialize)]
pub struct CreateTokenRequest {
    pub mint_authority: String,
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
pub struct SignMessageResponse {
    pub signature: String,
    pub public_key: String,
    pub message: String,
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
    Error { success: bool, error: String },
}

#[handler]
fn generate_keypair() -> PoemResult<Json<ApiResponse>> {
    match std::panic::catch_unwind(|| {
        let keypair = Keypair::new();
        let secret_bytes = keypair.to_bytes();
        
        KeypairResponse {
            pubkey: keypair.pubkey().to_string(),
            secret: secret_bytes.to_base58(),
        }
    }) {
        Ok(response) => {
            Ok(Json(ApiResponse::Success {
                success: true,
                data: response,
            }))
        }
        Err(_) => {
            Ok(Json(ApiResponse::Error {
                success: false,
                error: "Failed to generate keypair".to_string(),
            }))
        }
    }
}

#[handler]
fn create_token(Json(payload): Json<CreateTokenRequest>) -> PoemResult<Json<ApiResponse>> {
    match std::panic::catch_unwind(|| -> Result<TokenCreateResponse, String> {
        let mint_authority = Pubkey::from_str(&payload.mint_authority)
            .map_err(|_| "Invalid mint authority pubkey".to_string())?;
        let mint = Pubkey::from_str(&payload.mint)
            .map_err(|_| "Invalid mint pubkey".to_string())?;

        let instruction = token_instruction::initialize_mint(
            &TOKEN_PROGRAM_ID,
            &mint,
            &mint_authority,
            None, // freeze_authority
            payload.decimals,
        ).map_err(|_| "Failed to create initialize mint instruction".to_string())?;

        let accounts: Vec<AccountMetaResponse> = instruction.accounts.iter().map(|account| {
            AccountMetaResponse {
                pubkey: account.pubkey.to_string(),
                is_signer: account.is_signer,
                is_writable: account.is_writable,
            }
        }).collect();

        let instruction_data = base64::encode(&instruction.data);

        Ok(TokenCreateResponse {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data,
        })
    }) {
        Ok(Ok(response)) => {
            Ok(Json(ApiResponse::TokenSuccess {
                success: true,
                data: response,
            }))
        }
        Ok(Err(error_msg)) => {
            Ok(Json(ApiResponse::Error {
                success: false,
                error: error_msg.to_string(),
            }))
        }
        Err(_) => {
            Ok(Json(ApiResponse::Error {
                success: false,
                error: "Failed to create token instruction".to_string(),
            }))
        }
    }
}

#[handler]
fn mint_token(Json(payload): Json<MintTokenRequest>) -> PoemResult<Json<ApiResponse>> {
    match std::panic::catch_unwind(|| -> Result<TokenMintResponse, String> {
        let mint = Pubkey::from_str(&payload.mint)
            .map_err(|_| "Invalid mint pubkey".to_string())?;
        let destination = Pubkey::from_str(&payload.destination)
            .map_err(|_| "Invalid destination pubkey".to_string())?;
        let authority = Pubkey::from_str(&payload.authority)
            .map_err(|_| "Invalid authority pubkey".to_string())?;

        let instruction = token_instruction::mint_to(
            &TOKEN_PROGRAM_ID,
            &mint,
            &destination,
            &authority,
            &[],
            payload.amount,
        ).map_err(|_| "Failed to create mint-to instruction".to_string())?;

        let accounts: Vec<AccountMetaResponse> = instruction.accounts.iter().map(|account| {
            AccountMetaResponse {
                pubkey: account.pubkey.to_string(),
                is_signer: account.is_signer,
                is_writable: account.is_writable,
            }
        }).collect();

        let instruction_data = base64::encode(&instruction.data);

        Ok(TokenMintResponse {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data,
        })
    }) {
        Ok(Ok(response)) => {
            Ok(Json(ApiResponse::TokenMintSuccess {
                success: true,
                data: response,
            }))
        }
        Ok(Err(error_msg)) => {
            Ok(Json(ApiResponse::Error {
                success: false,
                error: error_msg.to_string(),
            }))
        }
        Err(_) => {
            Ok(Json(ApiResponse::Error {
                success: false,
                error: "Failed to create mint token instruction".to_string(),
            }))
        }
    }
}

#[handler]
fn sign_message(Json(payload): Json<SignMessageRequest>) -> PoemResult<Json<ApiResponse>> {
    // Check for missing fields
    if payload.message.is_empty() || payload.secret.is_empty() {
        return Ok(Json(ApiResponse::Error {
            success: false,
            error: "Missing required fields".to_string(),
        }));
    }

    match std::panic::catch_unwind(|| -> Result<SignMessageResponse, String> {
        // Decode the base58 secret key
        let secret_bytes = payload.secret.from_base58()
            .map_err(|_| "Invalid base58 secret key".to_string())?;
        
        // Ensure the secret key is exactly 64 bytes
        if secret_bytes.len() != 64 {
            return Err("Invalid secret key length".to_string());
        }

        // Create keypair from secret bytes
        let keypair = Keypair::from_bytes(&secret_bytes)
            .map_err(|_| "Failed to create keypair from secret".to_string())?;

        // Sign the message
        let message_bytes = payload.message.as_bytes();
        let signature = keypair.sign_message(message_bytes);

        Ok(SignMessageResponse {
            signature: base64::encode(&signature.as_ref()),
            public_key: keypair.pubkey().to_string(),
            message: payload.message,
        })
    }) {
        Ok(Ok(response)) => {
            Ok(Json(ApiResponse::SignMessageSuccess {
                success: true,
                data: response,
            }))
        }
        Ok(Err(error_msg)) => {
            Ok(Json(ApiResponse::Error {
                success: false,
                error: error_msg,
            }))
        }
        Err(_) => {
            Ok(Json(ApiResponse::Error {
                success: false,
                error: "Failed to sign message".to_string(),
            }))
        }
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
        .at("/generate_keypair", post(generate_keypair))
        .at("/token/create", post(create_token))
        .at("/token/mint", post(mint_token))
        .at("/message/sign", post(sign_message));

    println!("running at http://0.0.0.0:80");
    Server::new(TcpListener::bind("0.0.0.0:80"))
        .name("solana-api")
        .run(app)
        .await
}