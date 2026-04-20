# Experimenting with LLMs for Reverse Engineering

## Setup

- Up-to-date **REMnux** lab
- **Claude** and **ChatGPT Pro** subscriptions
- Host machine running **MCP** on Ubuntu
- Public sandboxes such as **ANY.RUN** or **CAPE** for dynamic analysis

## Strengths

- Efficient on **obfuscated malicious Excel documents**
- Consistently provides:
  - recommendations
  - detection rules
  - IOCs
- Strong potential for **automation**
- Much more precise when combined with **dynamic analysis** from public sandboxes
- Good level of analysis when paired with **open-source intelligence**

## Limitations

- Performance varies significantly and depends heavily on the model  
  *(Claude often performs better than ChatGPT, but results can vary a lot even within the same model)*
- Very **token-consuming**
- Often defeated by **encryption**
- May hallucinate findings or incorrectly claim results taken from third-party reports or sandbox outputs
- Requires close guidance throughout the process  
  *(for example: identifying decryption constants, decrypting payloads, extracting configs, etc.)*
- Pro subscriptions remain **too limited in tokens** for sustained analysis
