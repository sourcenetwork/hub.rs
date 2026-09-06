use super::*;
use std::io::{BufRead, Read, Write};

async fn call(response: String, maximum: usize) -> Result<u64, ClientError> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut input = std::io::BufReader::new(&mut stream);
        let mut length = 0;
        loop {
            let mut line = String::new();
            assert_ne!(input.read_line(&mut line).unwrap(), 0);
            if line == "\r\n" {
                break;
            }
            if let Some((name, value)) = line.split_once(':')
                && name.eq_ignore_ascii_case("content-length")
            {
                length = value.trim().parse().unwrap();
            }
        }
        input.read_exact(&mut vec![0; length]).unwrap();
        stream.write_all(response.as_bytes()).unwrap();
    });
    let result = HubClient::new(format!("http://{address}"))
        .rpc_call_bounded("test", serde_json::json!([]), maximum)
        .await;
    server.join().unwrap();
    result
}

#[tokio::test]
async fn permission_transport_bounds_declared_and_chunked_responses() {
    let declared = "HTTP/1.1 200 OK\r\nContent-Length: 4096\r\nConnection: close\r\n\r\n";
    assert!(matches!(
        call(declared.into(), 128).await,
        Err(ClientError::ResponseTooLarge(128))
    ));
    let chunked = format!(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n100\r\n{}\r\n0\r\n\r\n",
        "x".repeat(256)
    );
    assert!(matches!(
        call(chunked, 128).await,
        Err(ClientError::ResponseTooLarge(128))
    ));
}

#[tokio::test]
async fn permission_transport_binds_response_id_before_returning_data() {
    for (id, valid) in [(1, true), (2, false)] {
        let body = format!(r#"{{"jsonrpc":"2.0","id":{id},"result":42}}"#);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let result = call(response, 1024).await;
        if valid {
            assert_eq!(result.unwrap(), 42);
        } else {
            assert!(matches!(result, Err(ClientError::InvalidResponse(_))));
        }
    }
}
