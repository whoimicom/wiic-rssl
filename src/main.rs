use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::TcpStream;
use std::time::{Duration, SystemTime};

use chrono::{DateTime, Utc};
use native_tls::TlsConnector;
use tokio::time::interval;

// 检查单个域名的证书
async fn check_domain_certificate(domain: &str) -> Result<SystemTime, Box<dyn Error>> {
    // 这里我们使用系统命令来获取证书信息，确保跨平台兼容性
    #[cfg(target_os = "windows")]
    let output = std::process::Command::new("powershell.exe")
        .args([
            "-Command",
            &format!(
                "try {{ \
                    $tcpClient = New-Object Net.Sockets.TcpClient('{}', 443); \
                    $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false); \
                    $sslStream.AuthenticateAsClient('{}'); \
                    $cert = $sslStream.RemoteCertificate; \
                    $x509 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cert); \
                    $x509.NotAfter.ToString('o'); \
                    $sslStream.Close(); \
                    $tcpClient.Close(); \
                }} catch {{ \
                    Write-Error $_.Exception.Message; \
                }}", 
                domain, domain
            )
        ])
        .output()?;
    
    #[cfg(target_os = "linux")]
    let output = std::process::Command::new("bash")
        .args([
            "-c",
            &format!(
                "echo | openssl s_client -connect {}:443 2>/dev/null | openssl x509 -noout -enddate | cut -d= -f2", 
                domain
            )
        ])
        .output()?;
    
    #[cfg(target_os = "macos")]
    let output = std::process::Command::new("bash")
        .args([
            "-c",
            &format!(
                "echo | openssl s_client -connect {}:443 2>/dev/null | openssl x509 -noout -enddate | cut -d= -f2", 
                domain
            )
        ])
        .output()?;
    
    if output.status.success() {
        let stdout = String::from_utf8(output.stdout)?;
        let not_after_str = stdout.trim();
        
        if !not_after_str.is_empty() {
            // 解析证书过期日期
            #[cfg(target_os = "windows")]
            let not_after = chrono::DateTime::parse_from_rfc3339(not_after_str)?;
            
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            let not_after = chrono::NaiveDateTime::parse_from_str(not_after_str, "%b %d %H:%M:%S %Y %Z")?;
            
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            let not_after = chrono::DateTime::<Utc>::from_utc(not_after, Utc);
            
            let expiry_date: SystemTime = not_after.into();
            
            Ok(expiry_date)
        } else {
            Err("Failed to get certificate expiry date".into())
        }
    } else {
        let stderr = String::from_utf8(output.stderr)?;
        Err(format!("Command failed: {}", stderr).into())
    }
}

// 证书检查任务
async fn check_certificates() -> Result<(), Box<dyn Error>> {
    println!("=== Certificate Check Task Started at {}" , DateTime::<Utc>::from(SystemTime::now()).format("%Y-%m-%d %H:%M:%S UTC"));
    
    // 读取域名列表
    let file = File::open("src/domains.txt")?;
    let reader = BufReader::new(file);
    
    for line in reader.lines() {
        let domain = line?;
        if domain.is_empty() {
            continue;
        }
        
        println!("\nChecking domain: {}", domain);
        
        match check_domain_certificate(&domain).await {
            Ok(expiry_date) => {
                let now = SystemTime::now();
                let days_until_expiry = expiry_date.duration_since(now)?.as_secs() / (60 * 60 * 24);
                
                let expiry_date_utc: DateTime<Utc> = expiry_date.into();
                println!("  Expiry date: {}", expiry_date_utc.format("%Y-%m-%d %H:%M:%S UTC"));
                println!("  Days until expiry: {}", days_until_expiry);
                
                if days_until_expiry < 30 {
                    println!("  Status: ERROR - Certificate expires in less than 30 days!");
                } else {
                    println!("  Status: OK");
                }
            }
            Err(e) => {
                println!("  Status: ERROR - Could not check certificate: {}", e);
            }
        }
    }
    
    println!("\n=== Certificate Check Task Completed ===");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // 立即执行一次任务
    check_certificates().await?;
    
    // 创建一个每天执行一次的定时器（86400秒 = 1天）
    let mut interval = interval(Duration::from_secs(86400));
    
    println!("\n=== Scheduler Started, will run daily ===");
    
    // 循环执行任务
    loop {
        interval.tick().await;
        println!("\n--- Running scheduled certificate check ---");
        if let Err(e) = check_certificates().await {
            println!("Error running certificate check: {}", e);
        }
    }
}
