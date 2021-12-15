use crate::constants::*;
use anchor_lang::prelude::*;
use anchor_lang::solana_program::{sysvar, clock, program_option::COption};
use anchor_spl::token::{self, TokenAccount, Token, Mint};
use std::convert::Into;
use std::convert::TryInto;

declare_id!("TeSTKchdpa2FKNV6gYNAENpququb3aT2r1pD41tZw36");

mod constants {
    pub const TOKEN_MINT_PUBKEY: &str = "tEsTL8G8drugWztoCKrPpEAXV21qEajfHg4q45KYs6s";
    pub const X_STEP_DEPOSIT_REQUIREMENT: u64 = 10_000_000_000_000;
    pub const MIN_DURATION: u64 = 1;
}

const PRECISION: u128 = u64::MAX as u128;

pub fn updatePointsBalance(
    pool: &mut Account<Pool>,
    user: Option<&mut Box<Account<User>>>,
) -> Result<()> {
    let clock = clock::Clock::get().unwrap();
    if let Some(u) = user {
        u.pointsDebt = unDebitedPoints(
            u.balance_staked,
            pool.reward_per_token,
            u.last_update_time,
            clock.unix_timestamp.try_into().unwrap(),
        );
    }

    Ok(())
}

pub fn unDebitedPoints(
    balance_staked: u128,
    reward_per_token: u128,
    user_last_update_at: u128,
    current_timestamp: u128,
) -> u128 {
    return (current_timestamp as u128)
        .checked_sub(user_last_update_at as u128).unwrap()
        .checked_mul(reward_per_token as u128).unwrap()
        .checked_mul(balance_staked as u128).unwrap();
}

#[program]
pub mod nftfarming {
    use super::*;
    pub fn initialize_pool(
        ctx: Context<InitializePool>,
        pool_nonce: u8,
        reward_per_token: u128,
        nft_provider: Pubkey
    ) -> Result<()> {

        let pool = &mut ctx.accounts.pool;

        pool.authority = ctx.accounts.authority.key();
        pool.nonce = pool_nonce;
        pool.staking_mint = ctx.accounts.staking_mint.key();
        pool.staking_vault = ctx.accounts.staking_vault.key();
        pool.user_stake_count = 0;
        pool.reward_per_token = reward_per_token;
        pool.nft_provider = nft_provider;
        
        Ok(())
    }

    pub fn create_user(ctx: Context<CreateUser>, nonce: u8) -> Result<()> {
        let user = &mut ctx.accounts.user;
        user.pool = *ctx.accounts.pool.to_account_info().key;
        user.owner = *ctx.accounts.owner.key;
        user.points_redeemed = 0;
        user.pointsDebt = 0;
        user.balance_staked = 0;
        user.nonce = nonce;

        let pool = &mut ctx.accounts.pool;
        pool.user_stake_count = pool.user_stake_count.checked_add(1).unwrap();

        Ok(())
    }

    pub fn stake(ctx: Context<Stake>, amount: u64) -> Result<()> {
        if amount == 0 {
            return Err(ErrorCode::AmountMustBeGreaterThanZero.into());
        }

        let pool = &mut ctx.accounts.pool;

        let user_opt = Some(&mut ctx.accounts.user);
        updatePointsBalance(
            pool,
            user_opt,
        )
        .unwrap();
        
        let clock = clock::Clock::get().unwrap();
        ctx.accounts.user.balance_staked = ctx.accounts.user.balance_staked.checked_sub(amount as u128).unwrap();
        ctx.accounts.user.last_update_time = clock.unix_timestamp.try_into().unwrap();

        // Transfer tokens into the stake vault.
        {
            let cpi_ctx = CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.stake_from_account.to_account_info(),
                    to: ctx.accounts.staking_vault.to_account_info(),
                    authority: ctx.accounts.owner.to_account_info(), //todo use user account as signer
                },
            );
            token::transfer(cpi_ctx, amount)?;
        }

        Ok(())
    }



    pub fn unstake(ctx: Context<Stake>, spt_amount: u128) -> Result<()> {
        if spt_amount == 0 {
            return Err(ErrorCode::AmountMustBeGreaterThanZero.into());
        }

        let total_staked = ctx.accounts.staking_vault.amount;
        
        if ctx.accounts.user.balance_staked < spt_amount {
            return Err(ErrorCode::InsufficientFundUnstake.into());
        }

        let user_opt = Some(&mut ctx.accounts.user);
        updatePointsBalance(
            &mut ctx.accounts.pool,
            user_opt,
        )
        .unwrap();
        
        let clock = clock::Clock::get().unwrap();
        ctx.accounts.user.balance_staked = ctx.accounts.user.balance_staked.checked_sub(spt_amount).unwrap();
        ctx.accounts.user.last_update_time = clock.unix_timestamp.try_into().unwrap();

        // Transfer tokens from the pool vault to user vault.
        {
            let seeds = &[
                ctx.accounts.pool.to_account_info().key.as_ref(),
                &[ctx.accounts.pool.nonce],
            ];
            let pool_signer = &[&seeds[..]];

            let cpi_ctx = CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.staking_vault.to_account_info(),
                    to: ctx.accounts.stake_from_account.to_account_info(),
                    authority: ctx.accounts.pool_signer.to_account_info(),
                },
                pool_signer,
            );
            token::transfer(cpi_ctx, spt_amount.try_into().unwrap())?;
        }

        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(pool_nonce: u8)]
pub struct InitializePool<'info> {
    authority: UncheckedAccount<'info>,

    staking_mint: Box<Account<'info, Mint>>,
    #[account(
        constraint = staking_vault.mint == staking_mint.key(),
        constraint = staking_vault.owner == pool_signer.key(),
        //strangely, spl maintains this on owner reassignment for non-native accounts
        //we don't want to be given an account that someone else could close when empty
        //because in our "pool close" operation we want to assert it is still open
        constraint = staking_vault.close_authority == COption::None,
    )]
    staking_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        seeds = [
            pool.to_account_info().key.as_ref()
        ],
        bump = pool_nonce,
    )]
    pool_signer: UncheckedAccount<'info>,

    #[account(
        zero,
    )]
    pool: Box<Account<'info, Pool>>,
    
    token_program: Program<'info, Token>,
}


#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = user, space = 8 + 8)]
    pub my_account: Account<'info, Pool>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(nonce: u8)]
pub struct CreateUser<'info> {
    // Stake instance.
    #[account(
        mut
    )]
    pool: Box<Account<'info, Pool>>,
    // Member.
    #[account(
        init,
        payer = owner,
        seeds = [
            owner.key.as_ref(), 
            pool.to_account_info().key.as_ref()
        ],
        bump = nonce,
    )]
    user: Box<Account<'info, User>>,
    owner: Signer<'info>,
    // Misc.
    system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Stake<'info> {
    // Global accounts for the staking instance.
    #[account(
        mut, 
        has_one = staking_vault,
    )]
    pool: Box<Account<'info, Pool>>,
    #[account(
        mut,
        constraint = staking_vault.owner == *pool_signer.key,
    )]
    staking_vault: Box<Account<'info, TokenAccount>>,

    // User.
    #[account(
        mut, 
        has_one = owner, 
        has_one = pool,
        seeds = [
            owner.key.as_ref(), 
            pool.to_account_info().key.as_ref()
        ],
        bump = user.nonce,
    )]
    user: Box<Account<'info, User>>,
    owner: Signer<'info>,
    #[account(mut)]
    stake_from_account: Box<Account<'info, TokenAccount>>,

    // Program signers.
    #[account(
        seeds = [
            pool.to_account_info().key.as_ref()
        ],
        bump = pool.nonce,
    )]
    pool_signer: UncheckedAccount<'info>,

    // Misc.
    token_program: Program<'info, Token>,
}

#[derive(Debug, Clone, AnchorSerialize, AnchorDeserialize)]
pub struct NFTInfo {
    /// Mint of the NFT
    pub nft_mint: Pubkey,
    /// Vault to store NFT
    pub nft_vault: Pubkey,
    /// Points required to claim the NFT
    pub price: u128,
    /// Redeem Status
    pub redeemed: bool,
}

#[account]
pub struct Pool {
    /// Priviledged account.
    pub authority: Pubkey,
    /// Mint of the token that can be staked.
    pub staking_mint: Pubkey,
    /// Vault to store staked tokens.
    pub staking_vault: Pubkey,
    /// Users staked
    pub user_stake_count: u32,
    /// NFT Information
    pub nft_info: Vec<NFTInfo>,
    /// nonce
    pub nonce: u8,
    /// reward per token
    pub reward_per_token: u128,
    /// authorized funders
    /// [] because short size, fixed account size, and ease of use on 
    /// client due to auto generated account size property
    pub nft_provider: Pubkey,
}

#[account]
#[derive(Default)]
pub struct User {
    /// Pool the this user belongs to.
    pub pool: Pubkey,
    /// The owner of this account.
    pub owner: Pubkey,
    /// The amount of points redeemed.
    pub points_redeemed: u128,
    /// Points Balance.
    pub pointsDebt: u128,
    /// The amount staked.
    pub balance_staked: u128,
    /// last update time.
    pub last_update_time: u128,
    /// Signer nonce.
    pub nonce: u8,
}

#[error]
pub enum ErrorCode {
    #[msg("Insufficient funds to unstake.")]
    InsufficientFundUnstake,
    #[msg("Amount must be greater than zero.")]
    AmountMustBeGreaterThanZero,
    #[msg("Provided funder is already authorized to fund.")]
    FunderAlreadyAuthorized,
    #[msg("Maximum funders already authorized.")]
    MaxFunders,
    #[msg("Cannot deauthorize the primary pool authority.")]
    CannotDeauthorizePoolAuthority,
    #[msg("Authority not found for deauthorization.")]
    CannotDeauthorizeMissingAuthority,
    #[msg("NFT has been claimed")]
    NFTClaimed,
    #[msg("Insufficient Points")]
    InsufficientPoints,
}