use super::i256::{i256_div, i256_mod};
use crate::{
    interpreter_types::{InterpreterTypes as ITy, StackTr},
    InstructionContext as Ictx, InstructionExecResult as Result,
};
use context_interface::Host;
use primitives::U256;

/// 256-bit arithmetic through the zkVM SDK a zkVM-agnostic guest is linked against
/// (`zkvm_u256_*`, feature `zkvm-u256`). Operands are `U256`'s little-endian limbs, the layout every
/// zkVM's 256-bit precompile reads, so nothing is converted; results follow the EVM opcode (wrapping,
/// zero for a zero divisor or modulus). Stack handling and gas are unchanged.
#[cfg(feature = "zkvm-u256")]
mod zkvm_u256 {
    use primitives::U256;

    type Limbs = [u64; 4];

    extern "C" {
        fn zkvm_u256_mul(a: *const Limbs, b: *const Limbs, result: *mut Limbs) -> i32;
        fn zkvm_u256_div(a: *const Limbs, b: *const Limbs, result: *mut Limbs) -> i32;
        fn zkvm_u256_mod(a: *const Limbs, b: *const Limbs, result: *mut Limbs) -> i32;
        fn zkvm_u256_addmod(
            a: *const Limbs,
            b: *const Limbs,
            n: *const Limbs,
            result: *mut Limbs,
        ) -> i32;
        fn zkvm_u256_mulmod(
            a: *const Limbs,
            b: *const Limbs,
            n: *const Limbs,
            result: *mut Limbs,
        ) -> i32;
        fn zkvm_u256_exp(base: *const Limbs, exponent: *const Limbs, result: *mut Limbs) -> i32;
    }

    macro_rules! binary {
        ($name:ident, $sym:ident) => {
            #[inline(always)]
            pub(super) fn $name(a: &U256, b: &U256) -> U256 {
                let mut result = [0; 4];
                unsafe { $sym(a.as_limbs(), b.as_limbs(), &mut result) };
                U256::from_limbs(result)
            }
        };
    }

    macro_rules! ternary {
        ($name:ident, $sym:ident) => {
            #[inline(always)]
            pub(super) fn $name(a: &U256, b: &U256, n: &U256) -> U256 {
                let mut result = [0; 4];
                unsafe { $sym(a.as_limbs(), b.as_limbs(), n.as_limbs(), &mut result) };
                U256::from_limbs(result)
            }
        };
    }

    binary!(mul, zkvm_u256_mul);
    binary!(div, zkvm_u256_div);
    binary!(rem, zkvm_u256_mod);
    binary!(exp, zkvm_u256_exp);
    ternary!(add_mod, zkvm_u256_addmod);
    ternary!(mul_mod, zkvm_u256_mulmod);
}

/// Implements the ADD instruction - adds two values from stack.
pub fn add<IT: ITy, H: ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    popn_top!([op1], op2, context.interpreter);
    *op2 = op1.wrapping_add(*op2);
    Ok(())
}

/// Implements the MUL instruction - multiplies two values from stack.
pub fn mul<IT: ITy, H: ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    popn_top!([op1], op2, context.interpreter);
    #[cfg(feature = "zkvm-u256")]
    {
        *op2 = zkvm_u256::mul(&op1, op2);
    }
    #[cfg(not(feature = "zkvm-u256"))]
    {
        *op2 = op1.wrapping_mul(*op2);
    }
    Ok(())
}

/// Implements the SUB instruction - subtracts two values from stack.
pub fn sub<IT: ITy, H: ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    popn_top!([op1], op2, context.interpreter);
    *op2 = op1.wrapping_sub(*op2);
    Ok(())
}

/// Implements the DIV instruction - divides two values from stack.
pub fn div<IT: ITy, H: ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    popn_top!([op1], op2, context.interpreter);
    #[cfg(feature = "zkvm-u256")]
    {
        *op2 = zkvm_u256::div(&op1, op2);
    }
    #[cfg(not(feature = "zkvm-u256"))]
    if !op2.is_zero() {
        *op2 = op1.wrapping_div(*op2);
    }
    Ok(())
}

/// Implements the SDIV instruction.
///
/// Performs signed division of two values from stack.
pub fn sdiv<IT: ITy, H: ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    popn_top!([op1], op2, context.interpreter);
    *op2 = i256_div(op1, *op2);
    Ok(())
}

/// Implements the MOD instruction.
///
/// Pops two values from stack and pushes the remainder of their division.
pub fn rem<IT: ITy, H: ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    popn_top!([op1], op2, context.interpreter);
    #[cfg(feature = "zkvm-u256")]
    {
        *op2 = zkvm_u256::rem(&op1, op2);
    }
    #[cfg(not(feature = "zkvm-u256"))]
    if !op2.is_zero() {
        *op2 = op1.wrapping_rem(*op2);
    }
    Ok(())
}

/// Implements the SMOD instruction.
///
/// Performs signed modulo of two values from stack.
pub fn smod<IT: ITy, H: ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    popn_top!([op1], op2, context.interpreter);
    *op2 = i256_mod(op1, *op2);
    Ok(())
}

/// Implements the ADDMOD instruction.
///
/// Pops three values from stack and pushes (a + b) % n.
pub fn addmod<IT: ITy, H: ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    popn_top!([op1, op2], op3, context.interpreter);
    #[cfg(feature = "zkvm-u256")]
    {
        *op3 = zkvm_u256::add_mod(&op1, &op2, op3);
    }
    #[cfg(not(feature = "zkvm-u256"))]
    {
        *op3 = op1.add_mod(op2, *op3);
    }
    Ok(())
}

/// Implements the MULMOD instruction.
///
/// Pops three values from stack and pushes (a * b) % n.
pub fn mulmod<IT: ITy, H: ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    popn_top!([op1, op2], op3, context.interpreter);
    #[cfg(feature = "zkvm-u256")]
    {
        *op3 = zkvm_u256::mul_mod(&op1, &op2, op3);
    }
    #[cfg(not(feature = "zkvm-u256"))]
    {
        *op3 = op1.mul_mod(op2, *op3);
    }
    Ok(())
}

/// Implements the EXP instruction - exponentiates two values from stack.
pub fn exp<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    popn_top!([op1], op2, context.interpreter);
    gas!(
        context.interpreter,
        context.host.gas_params().exp_cost(*op2)
    );
    #[cfg(feature = "zkvm-u256")]
    {
        *op2 = zkvm_u256::exp(&op1, op2);
    }
    #[cfg(not(feature = "zkvm-u256"))]
    {
        *op2 = op1.pow(*op2);
    }
    Ok(())
}

/// Implements the `SIGNEXTEND` opcode as defined in the Ethereum Yellow Paper.
///
/// In the yellow paper `SIGNEXTEND` is defined to take two inputs, we will call them
/// `x` and `y`, and produce one output.
///
/// The first `t` bits of the output (numbering from the left, starting from 0) are
/// equal to the `t`-th bit of `y`, where `t` is equal to `256 - 8(x + 1)`.
///
/// The remaining bits of the output are equal to the corresponding bits of `y`.
///
/// **Note**: If `x >= 32` then the output is equal to `y` since `t <= 0`.
///
/// To efficiently implement this algorithm in the case `x < 32` we do the following.
///
/// Let `b` be equal to the `t`-th bit of `y` and let `s = 255 - t = 8x + 7`
/// (this is effectively the same index as `t`, but numbering the bits from the
/// right instead of the left).
///
/// We can create a bit mask which is all zeros up to and including the `t`-th bit,
/// and all ones afterwards by computing the quantity `2^s - 1`.
///
/// We can use this mask to compute the output depending on the value of `b`.
///
/// If `b == 1` then the yellow paper says the output should be all ones up to
/// and including the `t`-th bit, followed by the remaining bits of `y`; this is equal to
/// `y | !mask` where `|` is the bitwise `OR` and `!` is bitwise negation.
///
/// Similarly, if `b == 0` then the yellow paper says the output should start with all zeros,
/// then end with bits from `b`; this is equal to `y & mask` where `&` is bitwise `AND`.
pub fn signextend<IT: ITy, H: ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    popn_top!([ext], x, context.interpreter);
    // For 31 we also don't need to do anything.
    if ext < U256::from(31) {
        let ext = ext.as_limbs()[0];
        let bit_index = (8 * ext + 7) as usize;
        let bit = x.bit(bit_index);
        let mask = (U256::from(1) << bit_index) - U256::from(1);
        *x = if bit { *x | !mask } else { *x & mask };
    }
    Ok(())
}
