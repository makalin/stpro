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

## **Example: Using stpro with Applications**

stpro works with any application that supports SOCKS5 proxies. Here are some examples:

### **Testing with curl:**
```bash
# Start stpro
./target/release/stpro 1080

# In another terminal, test with curl
curl --socks5 127.0.0.1:1080 https://www.google.com
```

### **Using with Discord (macOS):**

**Note:** Some Discord versions may not respect SOCKS5 proxy settings via command-line flags or environment variables. If Discord doesn't connect through the proxy, you may need to:

1. **Use system-level proxy settings** (macOS System Preferences → Network → Advanced → Proxies)
2. **Use a proxy management tool** that can force applications to use SOCKS5
3. **Use Discord's web version** in a browser configured to use the proxy

**To try with Discord:**

**Skip Discord's update check** (recommended to avoid update check failures):
1. Edit Discord's settings file:
   ```bash
   nano ~/Library/Application\ Support/discord/settings.json
   ```
2. Add this line to the JSON object (make sure to add a comma after the last property):
   ```json
   "SKIP_HOST_UPDATE": true
   ```
3. Save and exit (Ctrl+O, Enter, Ctrl+X in nano)

   Or use this command to add it automatically:
   ```bash
   python3 -c "import json; f=open('$HOME/Library/Application Support/discord/settings.json'); d=json.load(f); f.close(); d['SKIP_HOST_UPDATE']=True; f=open('$HOME/Library/Application Support/discord/settings.json','w'); json.dump(d,f,indent=2); f.close()"
   ```

**Launch Discord with proxy:**
1. Start stpro:  
   `./target/release/stpro 1080`

2. Quit Discord completely (Cmd+Q)

3. Launch Discord with proxy flag:  
   `/Applications/Discord.app/Contents/MacOS/Discord --proxy-server="socks5://127.0.0.1:1080"`

   Or try with environment variables:
   ```bash
   export ALL_PROXY=socks5://127.0.0.1:1080
   /Applications/Discord.app/Contents/MacOS/Discord
   ```

4. Watch the stpro logs to verify traffic is being tunneled:  
   `[*] Tunneling to: gateway.discord.gg:443`

**If Discord doesn't show connections in stpro logs**, Discord isn't using the proxy. The proxy itself is working correctly (test with curl to verify).

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
