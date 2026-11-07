//! 根 token 比较：控制面的 API 与指标端口共用一个实现。
//!
//! 比较必须与内容无关地耗时 —— 逐字节异或后聚合，而不是 `==` 在第一个
//! 不同的字节就返回。长度不等时立即返回 false 只泄露长度，不泄露内容。
pub fn same(left: &str, right: &str) -> bool {
    left.len() == right.len()
        && left
            .bytes()
            .zip(right.bytes())
            .fold(0_u8, |value, (a, b)| value | (a ^ b))
            == 0
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_exact_matches_are_equal() {
        assert!(same("Bearer abc", "Bearer abc"));
        assert!(!same("Bearer abc", "Bearer abd"));
        assert!(!same("Bearer abc", "Bearer abcdef"));
        assert!(!same("", "Bearer "));
        // 前缀相同、只差最后一位也必须拒绝（早期实现用 starts_with 的真实缺陷）。
        assert!(!same("Bearer 0000", "Bearer 0001"));
    }
}
