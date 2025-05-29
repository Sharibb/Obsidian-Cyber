## Presentation Layer of OSI


The **Presentation Layer (Layer 6)** of the OSI model is responsible for data translation, encryption, and compression to ensure that information sent by the application layer of one system is readable by the application layer of another system. Here’s a breakdown of its key functions:

### Key Responsibilities:
1. **Data Translation/Formatting**  
   - Converts data between formats (e.g., ASCII to Unicode, JSON to XML) to ensure compatibility between different systems.  
   - Handles character encoding (e.g., UTF-8), serialization (e.g., converting objects to byte streams), and syntax differences.

1. **Encryption/Decryption**  
   - Secures data via protocols like SSL/TLS (though modern implementations often combine this with Layer 7).  
   - Ensures confidentiality and integrity during transmission.

1. **Compression/Decompression**  
   - Reduces data size for efficient transmission (e.g., gzip, ZIP).  

1. **Abstract Data Structures**  
   - Manages complex data structures (e.g., converting floating-point numbers between systems with different representations).

### Examples:
- **File Formats**: JPEG, MPEG, PDF (standardized presentation).  
