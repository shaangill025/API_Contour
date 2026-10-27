fn main() {
    if run().is_err() {
        eprintln!("local platform failed; check operator configuration and local services");
        std::process::exit(1);
    }
}

fn run() -> Result<(), contour_platform::PlatformError> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 1 && args.len() != 3 {
        return Err(contour_platform::PlatformError::Configuration);
    }
    let platform = contour_platform::Platform::from_file(std::path::Path::new(&args[0]))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| contour_platform::PlatformError::Unavailable)?;
    if args.len() == 3 {
        let business = std::sync::Arc::new(contour_platform::business::Business::from_file(
            std::path::Path::new(&args[1]),
        )?);
        runtime.block_on(platform.serve_application(business, std::path::Path::new(&args[2])))
    } else {
        runtime.block_on(platform.serve())
    }
}
