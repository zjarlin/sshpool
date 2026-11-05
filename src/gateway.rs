use anyhow::Result;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Semaphore,
};

/// 透传 SSH 字节流，认证、PTY、SFTP 和转发全部由后端 OpenSSH 完成。
pub async fn serve(listener: TcpListener, backend: SocketAddr) -> Result<()> {
    let slots = Arc::new(Semaphore::new(64));
    loop {
        let permit = slots.clone().acquire_owned().await?;
        let (mut client, _) = listener.accept().await?;
        tokio::spawn(async move {
            let _permit = permit;
            let result = async {
                let mut server =
                    tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(backend))
                        .await??;
                client.set_nodelay(true)?;
                server.set_nodelay(true)?;
                tokio::io::copy_bidirectional(&mut client, &mut server).await?;
                Ok::<_, anyhow::Error>(())
            }
            .await;
            if let Err(error) = result {
                eprintln!("SSH connection: {error}");
            }
        });
    }
}
