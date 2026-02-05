use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::time::{Duration, SystemTime};

use chrono::{DateTime, Local, Utc};
use dirs::home_dir;

use tokio_cron_scheduler::{Job, JobScheduler};

// 发送企业微信webhook消息
async fn send_wechat_webhook(domain: &str, days: u64) -> Result<(), Box<dyn Error + Send + Sync>> {
    // 企业微信webhook URL，需要替换为实际的webhook URL
    let webhook_url = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=YOUR_WEBHOOK_KEY";
    
    // 构建消息内容
    let content = format!("域名 {} 证书有效期剩余 {} 天，请及时更新！", domain, days);
    let message = serde_json::Value::Object(serde_json::Map::from_iter(vec![
        ("msgtype".to_string(), serde_json::Value::String("text".to_string())),
        ("text".to_string(), serde_json::Value::Object(serde_json::Map::from_iter(vec![
            ("content".to_string(), serde_json::Value::String(content)),
        ]))),
    ]));
    
    // 发送HTTP请求
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    
    let response = client.post(webhook_url)
        .json(&message)
        .send()
        .await?;
    
    println!("Webhook response status: {}", response.status());
    Ok(())
}

// 检查单个域名的证书
async fn check_domain_certificate(domain: &str) -> Result<SystemTime, Box<dyn Error + Send + Sync>> {
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

async fn check_certificates() -> Result<(), Box<dyn Error + Send + Sync>> {
    // 使用本地时间打印
    println!("=== Certificate Check Task Started at {}" , Local::now().format("%Y-%m-%d %H:%M:%S %Z"));
    println!("=== Certificate Check Task Started at {}" , DateTime::<Utc>::from(SystemTime::now()).format("%Y-%m-%d %H:%M:%S UTC"));

    let home_dir = home_dir().ok_or("Could not get home directory")?;
    // let project_dir = home_dir.join("wiic-rssl");
    let project_name = env!("CARGO_PKG_NAME");
    let project_dir = home_dir.join(project_name);

    let domains_path = project_dir.join("domains.txt");
    
    println!("Reading domains from: {:?}", domains_path);
    
    let file = File::open(domains_path)?;
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
                
                // 使用本地时间打印
                let expiry_date_local = DateTime::<Local>::from(expiry_date);
                println!("  Expiry date: {}", expiry_date_local.format("%Y-%m-%d %H:%M:%S %Z"));
                println!("  Days until expiry: {}", days_until_expiry);
                
                if days_until_expiry < 10 {
                    println!("  Status: ERROR - Certificate expires in less than 10 days!");
                    // 发送企业微信webhook通知
                    if let Err(e) = send_wechat_webhook(&domain, days_until_expiry).await {
                        println!("  Failed to send webhook: {}", e);
                    }
                } else if days_until_expiry < 30 {
                    println!("  Status: WARNING - Certificate expires in less than 30 days!");
                } else {
                    println!("  Status: OK");
                }
            }
            Err(e) => {
                println!("  Status: ERROR - Could not check certificate: {}", e);
            }
        }
    }
    
    // 使用本地时间打印
    println!("=== Certificate Check Task Completed at {} ===" , Local::now().format("%Y-%m-%d %H:%M:%S %Z"));
    println!("=== Certificate Check Task Started at {}" , DateTime::<Utc>::from(SystemTime::now()).format("%Y-%m-%d %H:%M:%S UTC"));

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    // 立即执行一次任务
    check_certificates().await?;
    
    // 创建调度器
    let mut scheduler = JobScheduler::new().await?;
    
    // 添加一个每分钟执行的任务，用于测试
    let test_job = Job::new_async("0 * * * * *", |_uuid, _l| {
        Box::pin(async move {
            // 使用本地时间打印
            println!("\n--- Running test task at {}" , Local::now().format("%Y-%m-%d %H:%M:%S %Z"));
        })
    })?;
    scheduler.add(test_job).await?;
    
    // 创建每天9点10分执行的任务（cron表达式：秒 分 时 日 月 星期）
    let job = Job::new_async("0 10 9 * * *", |_uuid, _l| {
        Box::pin(async move {
            // 使用本地时间打印
            println!("\n--- Running scheduled certificate check at {}" , Local::now().format("%Y-%m-%d %H:%M:%S %Z"));
            if let Err(e) = check_certificates().await {
                println!("Error running certificate check: {}", e);
            }
        })
    })?;
    
    // 添加任务到调度器
    scheduler.add(job).await?;
    
    // 启动调度器
    println!("\n=== Scheduler Started, will run daily at 09:10 ===");
    println!("Test task will run every minute to verify scheduler is working");
    scheduler.start().await?;
    
    // 等待信号以保持程序运行
    tokio::signal::ctrl_c().await?;
    
    // 关闭调度器
    scheduler.shutdown().await?;
    
    Ok(())
}
