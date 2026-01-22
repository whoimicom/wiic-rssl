use std::error::Error;
use std::fs::copy;
use std::path::Path;

fn main() -> Result<(), Box<dyn Error>> {
    // 获取用户目录
    let home_dir = dirs::home_dir().ok_or("Could not get home directory")?;
    let project_dir = home_dir.join("wiic-rssl");
    
    // 创建项目目录
    std::fs::create_dir_all(&project_dir)?;
    
    // 复制domains.txt文件
    let src_path = Path::new("src/domains.txt");
    let dest_path = project_dir.join("domains.txt");
    
    copy(src_path, dest_path)?;
    
    println!("Domains.txt copied to: {:?}", dest_path);
    Ok(())
}
