#[cfg(test)]
mod test {

    use set04::{run_hmac_server,run_hmac_client};

    #[test]
    fn test_c31() {
        run_hmac_server();
        assert_eq!(true,run_hmac_client());
    }

}
