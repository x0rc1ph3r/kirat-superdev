use poem::{
    Route, Server, get, handler,
    listener::TcpListener,
    post,
    web::{Json},
    Result as PoemResult,
};

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
    match std::panic::catch_unwind(|| -> PoemResult<Json<ApiResponse>> {
        // Parse mint_authority
        let mint_authority = match SolanaPubkey::from_str(&payload.mint_authority) {
            Ok(pubkey) => pubkey,
            Err(_) => {
                return Ok(Json(ApiResponse::Error {
                    success: false,
                    error: "Invalid mint authority pubkey".to_string(),
                }));
            }
        };

        // Parse mint
        let mint = match SolanaPubkey::from_str(&payload.mint) {
            Ok(pubkey) => pubkey,
            Err(_) => {
                return Ok(Json(ApiResponse::Error {
                    success: false,
                    error: "Invalid mint pubkey".to_string(),
                }));
            }
        };

        // Create initialize_mint instruction
        let instruction = match token_instruction::initialize_mint(
            &TOKEN_PROGRAM_ID,
            &mint,
            &mint_authority,
            None, // freeze_authority
            payload.decimals,
        ) {
            Ok(instr) => instr,
            Err(_) => {
                return Ok(Json(ApiResponse::Error {
                    success: false,
                    error: "Failed to create token instruction".to_string(),
                }));
            }
        };

        let accounts: Vec<AccountMetaResponse> = instruction.accounts.iter().map(|account| {
            AccountMetaResponse {
                pubkey: account.pubkey.to_string(),
                is_signer: account.is_signer,
                is_writable: account.is_writable,
            }
        }).collect();

        let instruction_data = base64::encode(&instruction.data);

        Ok(Json(ApiResponse::TokenSuccess {
            success: true,
            data: TokenCreateResponse {
                program_id: instruction.program_id.to_string(),
                accounts,
                instruction_data,
            },
        }))
    }) {
        Ok(result) => result,
        Err(_) => Ok(Json(ApiResponse::Error {
            success: false,
            error: "Failed to create token instruction".to_string(),
        })),
    }
}
#[handler]
fn mint_token(Json(payload): Json<MintTokenRequest>) -> PoemResult<Json<ApiResponse>> {
    match std::panic::catch_unwind(|| -> PoemResult<Json<ApiResponse>> {
        // Parse mint pubkey
        let mint = match SolanaPubkey::from_str(&payload.mint) {
            Ok(pubkey) => pubkey,
            Err(_) => {
                return Ok(Json(ApiResponse::Error {
                    success: false,
                    error: "Invalid mint pubkey".to_string(),
                }));
            }
        };

        // Parse destination pubkey
        let destination = match SolanaPubkey::from_str(&payload.destination) {
            Ok(pubkey) => pubkey,
            Err(_) => {
                return Ok(Json(ApiResponse::Error {
                    success: false,
                    error: "Invalid destination pubkey".to_string(),
                }));
            }
        };

        // Parse authority pubkey
        let authority = match SolanaPubkey::from_str(&payload.authority) {
            Ok(pubkey) => pubkey,
            Err(_) => {
                return Ok(Json(ApiResponse::Error {
                    success: false,
                    error: "Invalid authority pubkey".to_string(),
                }));
            }
        };

        // Build mint_to instruction
        let instruction = match token_instruction::mint_to(
            &TOKEN_PROGRAM_ID,
            &mint,
            &destination,
            &authority,
            &[], // signer pubkeys
            payload.amount,
        ) {
            Ok(instr) => instr,
            Err(_) => {
                return Ok(Json(ApiResponse::Error {
                    success: false,
                    error: "Failed to create mint token instruction".to_string(),
                }));
            }
        };

        let accounts: Vec<AccountMetaResponse> = instruction.accounts.iter().map(|account| {
            AccountMetaResponse {
                pubkey: account.pubkey.to_string(),
                is_signer: account.is_signer,
                is_writable: account.is_writable,
            }
        }).collect();

        let instruction_data = base64::encode(&instruction.data);

        Ok(Json(ApiResponse::TokenMintSuccess {
            success: true,
            data: TokenMintResponse {
                program_id: instruction.program_id.to_string(),
                accounts,
                instruction_data,
            },
        }))
    }) {
        Ok(result) => result,
        Err(_) => Ok(Json(ApiResponse::Error {
            success: false,
            error: "Failed to create mint token instruction".to_string(),
        })),
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

    match std::panic::catch_unwind(|| -> PoemResult<Json<ApiResponse>> {
        // Decode the base58 secret key
        let secret_bytes = match payload.secret.from_base58() {
            Ok(bytes) => bytes,
            Err(_) => {
                return Ok(Json(ApiResponse::Error {
                    success: false,
                    error: "Invalid base58 secret key".to_string(),
                }));
            }
        };

        // Ensure the secret key is exactly 64 bytes
        if secret_bytes.len() != 64 {
            return Ok(Json(ApiResponse::Error {
                success: false,
                error: "Invalid secret key length".to_string(),
            }));
        }

        // Create keypair from secret bytes
        let keypair = match Keypair::from_bytes(&secret_bytes) {
            Ok(kp) => kp,
            Err(_) => {
                return Ok(Json(ApiResponse::Error {
                    success: false,
                    error: "Failed to create keypair from secret".to_string(),
                }));
            }
        };

        // Sign the message
        let message_bytes = payload.message.as_bytes();
        let signature = keypair.sign_message(message_bytes);

        Ok(Json(ApiResponse::SignMessageSuccess {
            success: true,
            data: SignMessageResponse {
                signature: base64::encode(signature.as_ref()),
                public_key: keypair.pubkey().to_string(),
                message: payload.message,
            },
        }))
    }) {
        Ok(result) => result,
        Err(_) => Ok(Json(ApiResponse::Error {
            success: false,
            error: "Failed to sign message".to_string(),
        })),
    }
}
#[handler]
fn verify_message(Json(payload): Json<VerifyMessageRequest>) -> PoemResult<Json<ApiResponse>> {
    // Check for missing fields
    if payload.message.is_empty() || payload.signature.is_empty() || payload.pubkey.is_empty() {
        return Ok(Json(ApiResponse::Error {
            success: false,
            error: "Missing required fields".to_string(),
        }));
    }

    match std::panic::catch_unwind(|| -> PoemResult<Json<ApiResponse>> {
        // Decode the base58 public key
        let pubkey = match SolanaPubkey::from_str(&payload.pubkey) {
            Ok(pk) => pk,
            Err(_) => {
                return Ok(Json(ApiResponse::Error {
                    success: false,
                    error: "Invalid public key".to_string(),
                }));
            }
        };

        // Decode the base64 signature
        let signature_bytes = match base64::decode(&payload.signature) {
            Ok(bytes) => bytes,
            Err(_) => {
                return Ok(Json(ApiResponse::Error {
                    success: false,
                    error: "Invalid base64 signature".to_string(),
                }));
            }
        };

        // Create signature from bytes
        let signature = match Signature::try_from(signature_bytes.as_slice()) {
            Ok(sig) => sig,
            Err(_) => {
                return Ok(Json(ApiResponse::Error {
                    success: false,
                    error: "Invalid signature format".to_string(),
                }));
            }
        };

        // Verify the signature
        let message_bytes = payload.message.as_bytes();
        let is_valid = signature.verify(&pubkey.as_ref(), message_bytes);

        Ok(Json(ApiResponse::VerifyMessageSuccess {
            success: true,
            data: VerifyMessageResponse {
                valid: is_valid,
                message: payload.message,
                pubkey: payload.pubkey,
            },
        }))
    }) {
        Ok(result) => result,
        Err(_) => Ok(Json(ApiResponse::Error {
            success: false,
            error: "Failed to verify message".to_string(),
        })),
    }
}
#[handler]
fn send_sol(Json(payload): Json<SendSolRequest>) -> PoemResult<Json<ApiResponse>> {
    // Check for missing fields and valid amount
    if payload.from.is_empty() || payload.to.is_empty() || payload.lamports == 0 {
        return Ok(Json(ApiResponse::Error {
            success: false,
            error: "Missing required fields or invalid amount".to_string(),
        }));
    }

    match std::panic::catch_unwind(|| -> PoemResult<Json<ApiResponse>> {
        // Parse from pubkey
        let from_pubkey = match SolanaPubkey::from_str(&payload.from) {
            Ok(pk) => pk,
            Err(_) => {
                return Ok(Json(ApiResponse::Error {
                    success: false,
                    error: "Invalid from address".to_string(),
                }));
            }
        };

        // Parse to pubkey
        let to_pubkey = match SolanaPubkey::from_str(&payload.to) {
            Ok(pk) => pk,
            Err(_) => {
                return Ok(Json(ApiResponse::Error {
                    success: false,
                    error: "Invalid to address".to_string(),
                }));
            }
        };

        // Create the transfer instruction
        let instruction = system_instruction::transfer(&from_pubkey, &to_pubkey, payload.lamports);

        let accounts: Vec<AccountMetaResponse> = instruction.accounts.iter().map(|account| {
            AccountMetaResponse {
                pubkey: account.pubkey.to_string(),
                is_signer: account.is_signer,
                is_writable: account.is_writable,
            }
        }).collect();

        let instruction_data = base64::encode(&instruction.data);

        Ok(Json(ApiResponse::TransferSuccess {
            success: true,
            data: TransferResponse {
                program_id: instruction.program_id.to_string(),
                accounts,
                instruction_data,
            },
        }))
    }) {
        Ok(result) => result,
        Err(_) => Ok(Json(ApiResponse::Error {
            success: false,
            error: "Failed to create SOL transfer instruction".to_string(),
        })),
    }
}
#[handler]
fn send_token(Json(payload): Json<SendTokenRequest>) -> PoemResult<Json<ApiResponse>> {
    // Check for missing fields and valid inputs
    if payload.destination.is_empty() || payload.mint.is_empty() || payload.owner.is_empty() || payload.amount == 0 {
        return Ok(Json(ApiResponse::Error {
            success: false,
            error: "Missing required fields or invalid amount".to_string(),
        }));
    }

    match std::panic::catch_unwind(|| -> PoemResult<Json<ApiResponse>> {
        // Parse mint
        let mint = match SolanaPubkey::from_str(&payload.mint) {
            Ok(pk) => pk,
            Err(_) => {
                return Ok(Json(ApiResponse::Error {
                    success: false,
                    error: "Invalid mint address".to_string(),
                }));
            }
        };

        // Parse owner
        let owner = match SolanaPubkey::from_str(&payload.owner) {
            Ok(pk) => pk,
            Err(_) => {
                return Ok(Json(ApiResponse::Error {
                    success: false,
                    error: "Invalid owner address".to_string(),
                }));
            }
        };

        // Parse destination
        let destination = match SolanaPubkey::from_str(&payload.destination) {
            Ok(pk) => pk,
            Err(_) => {
                return Ok(Json(ApiResponse::Error {
                    success: false,
                    error: "Invalid destination address".to_string(),
                }));
            }
        };

        // Derive ATAs
        let source_ata = spl_associated_token_account::get_associated_token_address(&owner, &mint);
        let destination_ata = spl_associated_token_account::get_associated_token_address(&destination, &mint);

        // Create transfer instruction
        let instruction = match token_instruction::transfer(
            &TOKEN_PROGRAM_ID,
            &source_ata,
            &destination_ata,
            &owner,
            &[],
            payload.amount,
        ) {
            Ok(instr) => instr,
            Err(_) => {
                return Ok(Json(ApiResponse::Error {
                    success: false,
                    error: "Failed to create token transfer instruction".to_string(),
                }));
            }
        };

        let accounts: Vec<AccountMetaResponse> = instruction.accounts.iter().map(|account| {
            AccountMetaResponse {
                pubkey: account.pubkey.to_string(),
                is_signer: account.is_signer,
                is_writable: account.is_writable,
            }
        }).collect();

        let instruction_data = base64::encode(&instruction.data);

        Ok(Json(ApiResponse::TransferSuccess {
            success: true,
            data: TransferResponse {
                program_id: instruction.program_id.to_string(),
                accounts,
                instruction_data,
            },
        }))
    }) {
        Ok(result) => result,
        Err(_) => Ok(Json(ApiResponse::Error {
            success: false,
            error: "Failed to create token transfer instruction".to_string(),
        })),
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