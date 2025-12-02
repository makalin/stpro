# **stpro (Stealth Proxy)**

**stpro** is a lightweight, high-performance SOCKS5 proxy server written in **Rust**. It is designed for network resilience research and Deep Packet Inspection (DPI) circumvention.  
By utilizing **Application Layer TCP Fragmentation**, stpro splits outgoing traffic into tiny, randomized chunks. This technique often confuses middleboxes and firewalls that rely on pattern matching (like SNI blocking) to filter traffic, effectively allowing connections to pass through restrictive networks.

## **Features**

* **⚡ Blazing Fast:** Built on Rust's tokio asynchronous runtime for high concurrency with minimal resource usage.  
* **🛡️ DPI Evasion:** Randomizes TCP packet sizes (fragmentation) to break signature detection.  
* **🔌 SOCKS5 Standard:** Compatible with any application that supports SOCKS5 (browsers, Discord, Telegram, curl, etc.).  
* **🍏 macOS Optimized:** Designed with macOS CLI workflows in mind.

## **Prerequisites**

* **Rust Toolchain:** You need Rust installed to build the project.  
  curl \--proto '=https' \--tlsv1.2 \-sSf \[https://sh.rustup.rs\](https://sh.rustup.rs) | sh

## **Installation**

1. Clone the repository:  
   git clone \[https://github.com/makalin/stpro.git\](https://github.com/makalin/stpro.git)  
   cd stpro

2. Build the project:  
   cargo build \--release

## **Usage**

Start the proxy server by specifying the local port you want to bind to (default is usually 1080).  
\# Run directly with cargo  
cargo run \--release \-- 1080

\# Or run the compiled binary  
./target/release/stpro 1080

You will see the following output indicating the server is active:  
\[\*\] SOCKS5 Proxy listening on 127.0.0.1:1080  
\[\*\] Configure your application to use Proxy: 127.0.0.1:1080

## **Example: Bypassing Discord Restrictions on macOS**

Electron-based apps like Discord respect command-line proxy flags. To tunnel Discord traffic through stpro:

1. Start stpro in one terminal window:  
   cargo run \-- 1080

2. Quit Discord completely (Cmd+Q).  
3. Launch Discord from a **new** terminal window with the proxy flag:  
   /Applications/Discord.app/Contents/MacOS/Discord \--proxy-server="socks5://127.0.0.1:1080"

4. Watch the stpro logs to verify traffic is being tunneled:  
   \[\*\] Tunneling to: gateway.discord.gg:443

## **How It Works**

Traditional DPI systems analyze the first few packets of a connection to identify protocols (like the TLS Client Hello). stpro acts as a middleman:

1. It accepts a standard connection from your app (Discord).  
2. It connects to the destination server.  
3. When forwarding data from your app to the server, it **fragments** the byte stream into chunks of random sizes (1-50 bytes) and forces immediate flushing to the network stack.

This fragmentation spreads keywords (like server names in SNI) across multiple TCP packets, making it computationally expensive or impossible for many real-time firewalls to reconstruct and block the connection.

## **Disclaimer**

This tool is a Proof of Concept (PoC) developed for **educational purposes and network research**. It is intended to demonstrate how protocol fragmentation affects network middleboxes. Users are responsible for complying with all local laws and network policies.

## **Author**

**Mehmet T. AKALIN**

* **GitHub:** [makalin](https://github.com/makalin)  
* **Company:** [Digital Vision](https://dv.com.tr)  
* **LinkedIn:** [Mehmet T. AKALIN](https://www.linkedin.com/in/makalin/)  
* **X (Twitter):** [@makalin](https://x.com/makalin)
