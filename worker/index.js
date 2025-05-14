// Skip importing the entire AWS SDK which has Node.js dependencies
// Instead, we'll implement a direct S3 client using fetch API which is fully compatible with Workers

// GCS authentication helper
async function getGCSAccessToken(env) {
  const now = Math.floor(Date.now() / 1000);
  const expiration = now + 3600; // Token valid for 1 hour
  
  const claim = {
    iss: env.GCP_CLIENT_EMAIL,
    scope: "https://www.googleapis.com/auth/devstorage.read_write",
    aud: "https://oauth2.googleapis.com/token",
    exp: expiration,
    iat: now
  };
  
  // Base64 URL encode the header
  const header = { alg: "RS256", typ: "JWT" };
  const encodedHeader = btoa(JSON.stringify(header))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  
  // Base64 URL encode the claim
  const encodedClaim = btoa(JSON.stringify(claim))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  
  // Create the content to sign
  const content = `${encodedHeader}.${encodedClaim}`;
  
  // Convert the private key from env var
  const privateKey = env.GCP_PRIVATE_KEY.replace(/\\n/g, "\n");
  
  // Use WebCrypto API to sign the JWT
  const encoder = new TextEncoder();
  const data = encoder.encode(content);
  
  // Import the private key
  const importedKey = await crypto.subtle.importKey(
    "pkcs8",
    pemToArrayBuffer(privateKey),
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: { name: "SHA-256" }
    },
    false,
    ["sign"]
  );
  
  // Sign the data
  const signature = await crypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" },
    importedKey,
    data
  );
  
  // Convert signature to Base64 URL encoded
  const encodedSignature = arrayBufferToBase64Url(signature);
  
  // Create the complete JWT
  const jwt = `${content}.${encodedSignature}`;
  
  // Exchange JWT for access token
  const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
  });
  
  const tokenData = await tokenResponse.json();
  
  if (!tokenResponse.ok) {
    throw new Error(`Failed to get GCS token: ${JSON.stringify(tokenData)}`);
  }
  
  return tokenData.access_token;
}

// S3 API helper functions using fetch directly
// Generate AWS Signature V4 for S3 requests
async function getS3Signature(env, method, path, host, queryParams = "", headers = {}, body = null) {
  const accessKey = env.AWS_ACCESS_KEY_ID;
  const secretKey = env.AWS_SECRET_ACCESS_KEY;
  const region = env.AWS_REGION;
  const service = "s3";
  
  // Date handling for AWS Signature - Use UTC
  const date = new Date();
  const amzDate = date.toISOString().replace(/[:\-]|\.\d{3}/g, "");
  const dateStamp = amzDate.slice(0, 8);
  
  // Add required headers - ensure they're all lowercase
  headers["x-amz-date"] = amzDate;
  headers["host"] = host;
  
  // Get content hash from headers or calculate it
  let contentHash;
  
  // If header already contains the content hash, use it
  if (headers["x-amz-content-sha256"]) {
    contentHash = headers["x-amz-content-sha256"];
  } 
  // Otherwise calculate it
  else if (body) {
    const data = body instanceof Uint8Array ? body : new TextEncoder().encode(body);
    contentHash = await sha256Buffer(data);
    headers["x-amz-content-sha256"] = contentHash;
  } else {
    contentHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; // Empty string hash
    headers["x-amz-content-sha256"] = contentHash;
  }
  
  // Create canonical request with normalized headers
  // Headers must be sorted alphabetically by lowercase header name
  const sortedHeaderKeys = Object.keys(headers).sort((a, b) => 
    a.toLowerCase().localeCompare(b.toLowerCase())
  );
  
  // Canonical headers must have no spaces between the colon and the value
  const canonicalHeaders = sortedHeaderKeys
    .map(key => {
      const headerName = key.toLowerCase();
      // Ensure proper formatting - trim with no spaces after colon
      const headerValue = headers[key].trim().replace(/\s+/g, " ");
      return `${headerName}:${headerValue}`;
    })
    .join("\n") + "\n";
  
  const signedHeaders = sortedHeaderKeys
    .map(key => key.toLowerCase())
    .join(";");
  
  // Canonical URI path must be URL-encoded twice for certain special characters in the path
  // but for most common characters like '/' we keep them as is
  let canonicalPath = path;
  if (path !== "/") {
    // Just ensure it's properly encoded, but leave / characters
    canonicalPath = path.replace(/\/+/g, "/");
  }
  
  // Build canonical query string - must be in lexicographic order by parameter name
  let canonicalQueryString = queryParams;
  if (typeof queryParams === "object") {
    const sortedParams = Object.keys(queryParams).sort();
    canonicalQueryString = sortedParams.map(key => 
      `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`
    ).join("&");
  }
  
  const canonicalRequest = [
    method,
    canonicalPath,
    canonicalQueryString,
    canonicalHeaders,
    signedHeaders,
    contentHash,
  ].join("\n");
  
  // Create string to sign
  const algorithm = "AWS4-HMAC-SHA256";
  const scope = `${dateStamp}/${region}/${service}/aws4_request`;
  
  const canonicalRequestHash = await sha256(canonicalRequest);
  const stringToSign = [
    algorithm,
    amzDate,
    scope,
    canonicalRequestHash,
  ].join("\n");
  
  // Calculate signature
  const kDate = await hmacSha256("AWS4" + secretKey, dateStamp);
  const kRegion = await hmacSha256(kDate, region);
  const kService = await hmacSha256(kRegion, service);
  const kSigning = await hmacSha256(kService, "aws4_request");
  const signature = await hmacSha256(kSigning, stringToSign, "hex");
  
  // Log diagnostic information
  console.log("Canonical Request:", canonicalRequest);
  console.log("String to Sign:", stringToSign);
  console.log("Signed Headers:", signedHeaders);
  
  // Create authorization header
  const authorizationHeader = `${algorithm} Credential=${accessKey}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  
  return authorizationHeader;
}

// Helper functions for the signature process
async function sha256(message) {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256Buffer(buffer) {
  const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

async function hmacSha256(key, message, outputFormat = "") {
  const encoder = new TextEncoder();
  const messageBuffer = encoder.encode(message);
  
  let keyBuffer;
  if (typeof key === "string") {
    keyBuffer = encoder.encode(key);
  } else {
    keyBuffer = key;
  }
  
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBuffer,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, messageBuffer);
  
  if (outputFormat === "hex") {
    return Array.from(new Uint8Array(signature))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");
  }
  
  return new Uint8Array(signature);
}

// Helper to convert PEM format to ArrayBuffer
function pemToArrayBuffer(pem) {
  // Remove header, footer, and any whitespace
  const base64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s+/g, "");
  
  // Decode base64 to binary string
  const binaryString = atob(base64);
  
  // Convert to ArrayBuffer
  const buffer = new ArrayBuffer(binaryString.length);
  const view = new Uint8Array(buffer);
  for (let i = 0; i < binaryString.length; i++) {
    view[i] = binaryString.charCodeAt(i);
  }
  
  return buffer;
}

// Helper to convert ArrayBuffer to Base64URL
function arrayBufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

// GCS upload function
async function uploadToGCS(env, file, fileName, contentType) {
  try {
    const bucketName = env.GCP_BUCKET_NAME;
    const objectName = `gcs-${fileName}`;
    const accessToken = await getGCSAccessToken(env);
    
    // Convert file to arrayBuffer
    const arrayBuffer = await file.arrayBuffer();
    
    // Upload the file to GCS
    const uploadResponse = await fetch(
      `https://storage.googleapis.com/upload/storage/v1/b/${bucketName}/o?uploadType=media&name=${encodeURIComponent(objectName)}`,
      {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${accessToken}`,
          "Content-Type": contentType,
          "Content-Length": file.size.toString(),
          "x-goog-meta-source": "storage-comparison-tool"
        },
        body: arrayBuffer
      }
    );
    
    if (!uploadResponse.ok) {
      const errorText = await uploadResponse.text();
      throw new Error(`GCS upload failed: ${errorText}`);
    }
    
    const uploadData = await uploadResponse.json();
    
    // Get full metadata
    const metadataResponse = await fetch(
      `https://storage.googleapis.com/storage/v1/b/${bucketName}/o/${encodeURIComponent(objectName)}`,
      {
        headers: {
          "Authorization": `Bearer ${accessToken}`
        }
      }
    );
    
    if (!metadataResponse.ok) {
      const errorText = await metadataResponse.text();
      throw new Error(`GCS metadata fetch failed: ${errorText}`);
    }
    
    const metadata = await metadataResponse.json();
    
    return {
      key: objectName,
      etag: metadata.etag,
      size: parseInt(metadata.size, 10),
      metadata: {
        contentType: metadata.contentType,
        timeCreated: metadata.timeCreated,
        updated: metadata.updated,
        generation: metadata.generation,
        metageneration: metadata.metageneration,
        md5Hash: metadata.md5Hash,
        crc32c: metadata.crc32c
      }
    };
  } catch (error) {
    console.error("GCS upload error:", error);
    throw error;
  }
}

// GCS metadata function
async function getGCSMetadata(env, fileName) {
  try {
    const bucketName = env.GCP_BUCKET_NAME;
    const objectName = `gcs-${fileName}`;
    const accessToken = await getGCSAccessToken(env);
    
    const metadataResponse = await fetch(
      `https://storage.googleapis.com/storage/v1/b/${bucketName}/o/${encodeURIComponent(objectName)}`,
      {
        headers: {
          "Authorization": `Bearer ${accessToken}`
        }
      }
    );
    
    if (!metadataResponse.ok) {
      if (metadataResponse.status === 404) {
        return null;
      }
      const errorText = await metadataResponse.text();
      throw new Error(`GCS metadata fetch failed: ${errorText}`);
    }
    
    const metadata = await metadataResponse.json();
    
    return {
      key: objectName,
      size: parseInt(metadata.size, 10),
      metadata: {
        contentType: metadata.contentType,
        etag: metadata.etag,
        timeCreated: metadata.timeCreated,
        updated: metadata.updated,
        generation: metadata.generation,
        metageneration: metadata.metageneration,
        md5Hash: metadata.md5Hash,
        crc32c: metadata.crc32c
      }
    };
  } catch (error) {
    console.error("GCS metadata error:", error);
    throw error;
  }
}

// S3 upload function using direct API calls
async function uploadToS3(env, file, fileName, contentType) {
  try {
    // Prepare S3 request parameters
    const bucketName = env.S3_BUCKET_NAME;
    const region = env.AWS_REGION;
    const accessKeyId = env.AWS_ACCESS_KEY_ID;
    const secretAccessKey = env.AWS_SECRET_ACCESS_KEY;
    const service = "s3";
    const host = `${bucketName}.s3.${region}.amazonaws.com`;
    
    // Adjust objectKey to include s3- prefix for consistency with other providers
    const s3FileName = `s3-${fileName}`;
    const objectKey = encodeURIComponent(s3FileName).replace(/%2F/g, '/');
    const url = `https://${host}/${objectKey}`;
    
    console.log("S3 upload URL:", url);

    // Convert file to ArrayBuffer and then to Uint8Array
    const arrayBuffer = await file.arrayBuffer();
    const body = new Uint8Array(arrayBuffer);
    console.log("Body type:", typeof body, "instanceof Uint8Array:", body instanceof Uint8Array, "length:", body.length);
    
    // Calculate content hash from the body
    const contentHash = await sha256Hex(body);
    console.log("Content hash generated:", contentHash);
    
    // Prepare AWS authentication parameters
    const amzDate = getAmzDate();
    const shortDate = amzDate.slice(0, 8);

    // Prepare headers for the S3 request (all lowercase for signing)
    const headers = {
      "host": host,
      "x-amz-content-sha256": contentHash,
      "x-amz-date": amzDate,
      "content-type": contentType,
      "content-length": body.length.toString(),
      "x-amz-meta-source": "storage-comparison-tool",
      "x-amz-meta-originalfilename": fileName
    };

    // Create canonical request components for AWS signature
    const signedHeaders = Object.keys(headers).sort().join(";");
    const canonicalHeaders = Object.entries(headers)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}:${v.trim()}\n`)
      .join("");

    const canonicalRequest = [
      "PUT",
      `/${objectKey}`,
      "",  // No query parameters
      canonicalHeaders,
      signedHeaders,
      contentHash
    ].join("\n");
    
    console.log("S3 canonical request:\n", canonicalRequest);

    // Create the string to sign for AWS Signature v4
    const credentialScope = `${shortDate}/${region}/${service}/aws4_request`;
    const stringToSign = [
      "AWS4-HMAC-SHA256",
      amzDate,
      credentialScope,
      await sha256Hex(canonicalRequest)
    ].join("\n");
    
    console.log("S3 string to sign:\n", stringToSign);

    // Calculate the signature
    const signingKey = await getSigningKey(secretAccessKey, shortDate, region, service);
    const signature = await hmacHex(signingKey, stringToSign);

    // Create the authorization header
    const authorizationHeader =
      `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    // Convert lowercase header names to properly capitalized for the actual request
    const requestHeaders = {};
    for (const [key, value] of Object.entries(headers)) {
      requestHeaders[capitalizeHeader(key)] = value;
    }
    requestHeaders["Authorization"] = authorizationHeader;

    console.log("S3 request headers:", JSON.stringify(requestHeaders));

    // Make the S3 PUT request
    const response = await fetch(url, {
      method: "PUT",
      headers: requestHeaders,
      body
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error(`S3 upload failed with status ${response.status}:`, errorText);
      throw new Error(`S3 upload failed: ${response.status} - ${errorText}`);
    }

    // Extract the ETag from the response headers
    const etag = response.headers.get("ETag")?.replace(/"/g, "");
    console.log("S3 upload succeeded with ETag:", etag);

    return {
      key: s3FileName,
      etag,
      size: body.length,
      metadata: {
        contentType: contentType,
        lastModified: new Date().toISOString()
      }
    };
  } catch (err) {
    console.error("S3 Upload Error:", err);
    throw err;
  }
}

// Helper functions

function getAmzDate() {
  const now = new Date();
  // Ensure correct format: YYYYMMDDTHHMMSSZ (no double Z)
  return now.toISOString().replace(/[:-]|\.\d{3}/g, "");
}

async function sha256Hex(data) {
  // Ensure data is in a format that crypto.subtle.digest can accept
  let dataToHash;
  
  try {
    // Check data type and convert appropriately
    if (data instanceof Uint8Array) {
      dataToHash = data;
      console.log("sha256Hex received Uint8Array with length:", data.length);
    } else if (data instanceof ArrayBuffer) {
      dataToHash = new Uint8Array(data);
      console.log("sha256Hex received ArrayBuffer, converted to Uint8Array with length:", dataToHash.length);
    } else if (typeof data === 'string') {
      dataToHash = new TextEncoder().encode(data);
      console.log("sha256Hex received string, converted to Uint8Array with length:", dataToHash.length);
    } else if (data === null || data === undefined) {
      console.error("sha256Hex received null or undefined data");
      // Empty data hash
      return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    } else {
      // Try to intelligently handle other types
      console.error("sha256Hex received unexpected data type:", typeof data, ", attempting to convert");
      
      if (typeof data === 'object') {
        // Try to access any ArrayBuffer or buffer-like properties
        if (data.buffer instanceof ArrayBuffer) {
          dataToHash = new Uint8Array(data.buffer);
          console.log("Converted object with buffer property to Uint8Array with length:", dataToHash.length);
        } else {
          // Last resort, stringify the object and hash that
          const jsonString = JSON.stringify(data);
          dataToHash = new TextEncoder().encode(jsonString);
          console.log("Converted object to JSON string and then to Uint8Array with length:", dataToHash.length);
        }
      } else {
        // Convert anything else to string
        const strValue = String(data);
        dataToHash = new TextEncoder().encode(strValue);
        console.log("Converted value to string and then to Uint8Array with length:", dataToHash.length);
      }
    }
    
    // Ensure dataToHash is valid before proceeding
    if (!(dataToHash instanceof Uint8Array)) {
      throw new Error(`dataToHash is not a Uint8Array: ${typeof dataToHash}`);
    }
    
    // Double-check that our data is valid
    if (dataToHash.length === 0) {
      console.log("Empty data array, returning hash for empty string");
      return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    }
    
    const digest = await crypto.subtle.digest("SHA-256", dataToHash);
    return Array.from(new Uint8Array(digest))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");
  } catch (error) {
    console.error("Error in sha256Hex:", error, "for data type:", typeof data);
    // Return default hash for empty string as fallback
    return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  }
}

async function hmac(key, str) {
  try {
    // Ensure key is correctly formatted for importKey
    let keyData = key;
    if (!(key instanceof Uint8Array) && !(key instanceof ArrayBuffer)) {
      console.log("Converting key to Uint8Array in hmac function");
      keyData = new Uint8Array(key);
    }
    
    // Ensure string is encoded properly
    const enc = new TextEncoder().encode(str);
    
    // Import the key
    const cryptoKey = await crypto.subtle.importKey(
      "raw", 
      keyData, 
      { name: "HMAC", hash: "SHA-256" }, 
      false, 
      ["sign"]
    );
    
    // Sign the data
    const signature = await crypto.subtle.sign("HMAC", cryptoKey, enc);
    return new Uint8Array(signature);
  } catch (error) {
    console.error("Error in hmac function:", error);
    throw new Error(`HMAC calculation failed: ${error.message}`);
  }
}

async function hmacHex(key, str) {
  try {
    const hash = await hmac(key, str);
    return Array.from(hash).map(b => b.toString(16).padStart(2, "0")).join("");
  } catch (error) {
    console.error("Error in hmacHex function:", error);
    throw error; // Re-throw to be handled by the caller
  }
}

async function getSigningKey(secret, date, region, service) {
  try {
    console.log("Generating AWS signing key for date:", date, "region:", region, "service:", service);
    
    // Step 1: Create date key
    const kSecret = new TextEncoder().encode("AWS4" + secret);
    const kDate = await hmac(kSecret, date);
    
    // Step 2: Create region key
    const kRegion = await hmac(kDate, region);
    
    // Step 3: Create service key
    const kService = await hmac(kRegion, service);
    
    // Step 4: Create signing key
    const kSigning = await hmac(kService, "aws4_request");
    
    console.log("AWS signing key generated successfully");
    return kSigning;
  } catch (error) {
    console.error("Failed to generate AWS signing key:", error);
    throw error;
  }
}

function capitalizeHeader(header) {
  return header
    .split("-")
    .map(part => part.charAt(0).toUpperCase() + part.slice(1))
    .join("-");
}

// Helper function to create canonical headers with proper newline handling
function createCanonicalHeaders(headers) {
  return Object.entries(headers)
    .sort(([a], [b]) => a.toLowerCase().localeCompare(b.toLowerCase()))
    .map(([key, value]) => {
      const headerName = key.toLowerCase();
      const headerValue = value.trim().replace(/\s+/g, " ");
      return `${headerName}:${headerValue}\n`;
    })
    .join("");
}

// Helper function to create a canonical request properly
function createCanonicalRequest(method, path, queryString, headers, signedHeaders, contentHash) {
  return [
    method,
    path,
    queryString,
    createCanonicalHeaders(headers),
    signedHeaders,
    contentHash
  ].join("\n");
}

// Helper function to create string to sign
async function createStringToSign(algorithm, amzDate, scope, canonicalRequest) {
  return [
    algorithm,
    amzDate,
    scope,
    await sha256Hex(canonicalRequest)
  ].join("\n");
}


// S3 metadata function using direct API calls
async function getS3Metadata(env, fileName) {
  try {
    console.log("Fetching S3 metadata for:", fileName);
    const bucketName = env.S3_BUCKET_NAME;
    const region = env.AWS_REGION;
    
    // Use the exact same format as in the upload function for consistency
    const s3FileName = `s3-${fileName}`;
    
    // Create the HTTP path component with correct encoding
    const objectKey = encodeURIComponent(s3FileName).replace(/%2F/g, '/');
    const path = `/${objectKey}`;
    
    const host = `${bucketName}.s3.${region}.amazonaws.com`;
    const url = `https://${host}${path}`;
    
    // Set up headers for HEAD request - use lowercase for signature calculation
    const headers = {
      "host": host,
      "x-amz-date": getAmzDate(),
      "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // Empty body hash
    };
    
    // Get the date components for the authorization header
    const amzDate = headers["x-amz-date"];
    const dateStamp = amzDate.slice(0, 8);
    
    // Generate the signing key
    const signingKey = await getSigningKey(
      env.AWS_SECRET_ACCESS_KEY, 
      dateStamp, 
      region, 
      "s3"
    );
    
    // Create canonical request using our helper function
    const signedHeaders = Object.keys(headers).sort().join(";");
    
    // Use the helper function to create the canonical request properly
    const canonicalRequest = createCanonicalRequest(
      "HEAD",
      path,
      "",  // No query parameters
      headers,
      signedHeaders,
      headers["x-amz-content-sha256"]
    );
    
    console.log("S3 Metadata canonical request:", canonicalRequest);
    
    // Create the string to sign using our helper function
    const credentialScope = `${dateStamp}/${region}/s3/aws4_request`;
    const stringToSign = await createStringToSign(
      "AWS4-HMAC-SHA256",
      amzDate,
      credentialScope,
      canonicalRequest
    );
    
    console.log("S3 Metadata string to sign:\\n", stringToSign);
    
    // Calculate the signature
    const signature = await hmacHex(signingKey, stringToSign);
    
    // Create the authorization header
    const authorizationHeader =
      `AWS4-HMAC-SHA256 Credential=${env.AWS_ACCESS_KEY_ID}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
    
    // Prepare headers for the request - keep original case for required headers
    const requestHeaders = {
      "Host": host,
      "X-Amz-Date": amzDate,
      "X-Amz-Content-Sha256": headers["x-amz-content-sha256"],
      "Authorization": authorizationHeader
    };
    
    // Log for diagnostic purposes
    console.log("S3 Metadata URL:", url);
    console.log("S3 Metadata Headers:", JSON.stringify(requestHeaders));
    
    // Make HEAD request to get object metadata
    const response = await fetch(url, {
      method: "HEAD",
      headers: requestHeaders
    });
    
    // If we get a 403, try a different approach - use a GET request with the ?versioning param
    // This might work even when HEAD doesn't, depending on the bucket policy
    if (response.status === 403) {
      console.log("S3 HEAD request failed with 403. Trying alternate approach...");
      
      // Try to get object metadata via a GET request instead
      return await getS3MetadataAlternative(env, fileName);
    }
    
    if (!response.ok) {
      if (response.status === 404) {
        console.log(`S3 object not found: ${s3FileName}`);
        return null;
      }
      const errorText = await response.text();
      console.error(`S3 HEAD request failed: ${response.status}`, errorText);
      throw new Error(`S3 HEAD request failed: ${response.status} - ${errorText}`);
    }
    
    // Extract metadata from headers
    const contentLength = response.headers.get("Content-Length");
    const contentTypeHeader = response.headers.get("Content-Type");
    const lastModified = response.headers.get("Last-Modified");
    const etag = response.headers.get("ETag")?.replace(/"/g, "");
    const versionId = response.headers.get("x-amz-version-id") || "Not available";
    const storageClass = response.headers.get("x-amz-storage-class");
    const serverSideEncryption = response.headers.get("x-amz-server-side-encryption");
    const contentMD5 = response.headers.get("Content-MD5");
    
    console.log("S3 metadata retrieved successfully");
    
    return {
      key: s3FileName,
      size: parseInt(contentLength, 10),
      metadata: {
        contentType: contentTypeHeader,
        lastModified: lastModified ? new Date(lastModified).toISOString() : undefined,
        etag: etag,
        versionId: versionId,
        contentMD5: contentMD5,
        storageClass: storageClass,
        serverSideEncryption: serverSideEncryption
      }
    };
  } catch (error) {
    console.error("S3 metadata error:", error);
    throw error;
  }
}

// Alternative S3 metadata function that uses GET ?locations instead of HEAD 
// Some S3 bucket policies only allow GET but not HEAD
async function getS3MetadataAlternative(env, fileName) {
  try {
    console.log("Trying alternative S3 metadata approach for:", fileName);
    const bucketName = env.S3_BUCKET_NAME;
    const region = env.AWS_REGION;
    const s3FileName = `s3-${fileName}`;
    
    // This time we'll make a GET request to the bucket itself with the ?location query param
    const host = `${bucketName}.s3.${region}.amazonaws.com`;
    const path = "/";
    const queryParams = "location=";
    const url = `https://${host}${path}?${queryParams}`;
    
    // Set up headers for GET request
    const headers = {
      "host": host,
      "x-amz-date": getAmzDate(),
      "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    };
    
    // Get the date components for the authorization header
    const amzDate = headers["x-amz-date"];
    const dateStamp = amzDate.slice(0, 8);
    
    // Generate the signing key
    const signingKey = await getSigningKey(
      env.AWS_SECRET_ACCESS_KEY, 
      dateStamp, 
      region, 
      "s3"
    );
    
    // Create canonical request using helper functions
    const signedHeaders = Object.keys(headers).sort().join(";");
    
    const canonicalRequest = createCanonicalRequest(
      "GET",
      path,
      queryParams,
      headers,
      signedHeaders,
      headers["x-amz-content-sha256"]
    );
    
    console.log("S3 Alternative canonical request:\\n", canonicalRequest);
    
    // Create the string to sign using helper function
    const credentialScope = `${dateStamp}/${region}/s3/aws4_request`;
    const stringToSign = await createStringToSign(
      "AWS4-HMAC-SHA256",
      amzDate,
      credentialScope,
      canonicalRequest
    );
    
    console.log("S3 Alternative string to sign:\\n", stringToSign);
    
    // Calculate the signature
    const signature = await hmacHex(signingKey, stringToSign);
    
    // Create the authorization header
    const authorizationHeader =
      `AWS4-HMAC-SHA256 Credential=${env.AWS_ACCESS_KEY_ID}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
    
    // Prepare headers for the request
    const requestHeaders = {
      "Host": host,
      "X-Amz-Date": amzDate,
      "X-Amz-Content-Sha256": headers["x-amz-content-sha256"],
      "Authorization": authorizationHeader
    };
    
    console.log("S3 Alternative URL:", url);
    console.log("S3 Alternative Headers:", JSON.stringify(requestHeaders));
    
    // Make GET request to get bucket location
    const response = await fetch(url, {
      method: "GET",
      headers: requestHeaders
    });
    
    if (!response.ok) {
      const errorText = await response.text();
      console.error(`S3 alternative GET request failed: ${response.status}`, errorText);
      throw new Error(`S3 metadata retrieval failed with both methods. GET error: ${response.status} - ${errorText}`);
    }
    
    // Since we can communicate with the bucket, we can try a direct GET request to find the size 
    // by using range headers (asking for 0 bytes)
    const objectKey = encodeURIComponent(s3FileName).replace(/%2F/g, '/');
    const objectUrl = `https://${host}/${objectKey}`;
    
    // Create new headers for the object GET request with Range
    const objectHeaders = {
      "host": host,
      "x-amz-date": getAmzDate(),
      "range": "bytes=0-0",
      "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    };
    
    // Get date components
    const objAmzDate = objectHeaders["x-amz-date"];
    const objDateStamp = objAmzDate.slice(0, 8);
    
    // Sign the new request using helper functions
    const objSignedHeaders = Object.keys(objectHeaders).sort().join(";");
    
    const objCanonicalRequest = createCanonicalRequest(
      "GET",
      `/${objectKey}`,
      "",
      objectHeaders,
      objSignedHeaders,
      objectHeaders["x-amz-content-sha256"]
    );
    
    const objCredentialScope = `${objDateStamp}/${region}/s3/aws4_request`;
    const objStringToSign = await createStringToSign(
      "AWS4-HMAC-SHA256",
      objAmzDate,
      objCredentialScope,
      objCanonicalRequest
    );
    
    // Generate new signing key based on updated date
    const objSigningKey = await getSigningKey(
      env.AWS_SECRET_ACCESS_KEY, 
      objDateStamp, 
      region, 
      "s3"
    );
    
    const objSignature = await hmacHex(objSigningKey, objStringToSign);
    const objAuthHeader = `AWS4-HMAC-SHA256 Credential=${env.AWS_ACCESS_KEY_ID}/${objCredentialScope}, SignedHeaders=${objSignedHeaders}, Signature=${objSignature}`;
    
    // Prepare object request headers
    const objRequestHeaders = {
      "Host": host,
      "X-Amz-Date": objAmzDate,
      "Range": "bytes=0-0",
      "X-Amz-Content-Sha256": objectHeaders["x-amz-content-sha256"],
      "Authorization": objAuthHeader
    };
    
    console.log("S3 Object URL:", objectUrl);
    console.log("S3 Object Headers:", JSON.stringify(objRequestHeaders));
    
    // Make the GET request for the object with Range header
    const objResponse = await fetch(objectUrl, {
      method: "GET",
      headers: objRequestHeaders
    });
    
    if (!objResponse.ok) {
      console.error(`S3 object GET request failed: ${objResponse.status}`);
      // We'll still return some metadata, even if we can't get the size
      return {
        key: s3FileName,
        size: 0, // Unknown size
        metadata: {
          contentType: "application/octet-stream", // Default content type
          lastModified: new Date().toISOString(),
          etag: "Unknown",
          versionId: "Not available",
          note: "Limited metadata available due to bucket permissions"
        }
      };
    }
    
    // Get size from content-range header (format: "bytes 0-0/TOTAL_SIZE")
    const contentRange = objResponse.headers.get("Content-Range");
    let size = 0;
    
    if (contentRange) {
      const match = contentRange.match(/bytes 0-0\/(\d+)/);
      if (match && match[1]) {
        size = parseInt(match[1], 10);
      }
    }
    
    const contentTypeHeader = objResponse.headers.get("Content-Type");
    const lastModified = objResponse.headers.get("Last-Modified");
    const etag = objResponse.headers.get("ETag")?.replace(/"/g, "");
    
    console.log("S3 metadata retrieved via alternative method");
    
    return {
      key: s3FileName,
      size: size,
      metadata: {
        contentType: contentTypeHeader || "application/octet-stream",
        lastModified: lastModified ? new Date(lastModified).toISOString() : new Date().toISOString(),
        etag: etag || "Unknown",
        versionId: "Not available",
        note: "Retrieved via GET request (limited metadata available)"
      }
    };
  } catch (error) {
    console.error("S3 alternative metadata error:", error);
    throw error;
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    
    // Log environment check on startup (only keys presence, not the actual values)
    if (url.pathname === "/api/status") {
      console.log("Environment check:");
      console.log("- R2 Bucket: ", env.R2_BUCKET ? "Available" : "Missing");
      console.log("- AWS Environment:");
      console.log("  - S3_BUCKET_NAME: ", env.S3_BUCKET_NAME ? "Set" : "Missing");
      console.log("  - AWS_REGION: ", env.AWS_REGION ? "Set" : "Missing");
      console.log("  - AWS_ACCESS_KEY_ID: ", env.AWS_ACCESS_KEY_ID ? "Set" : "Missing");
      console.log("  - AWS_SECRET_ACCESS_KEY: ", env.AWS_SECRET_ACCESS_KEY ? 
        `Set (length: ${env.AWS_SECRET_ACCESS_KEY.length} chars)` : "Missing");
      console.log("- GCS Environment:");
      console.log("  - GCP_BUCKET_NAME: ", env.GCP_BUCKET_NAME ? "Set" : "Missing");
      console.log("  - GCP_PROJECT_ID: ", env.GCP_PROJECT_ID ? "Set" : "Missing");
      console.log("  - GCP_CLIENT_EMAIL: ", env.GCP_CLIENT_EMAIL ? "Set" : "Missing");
      console.log("  - GCP_PRIVATE_KEY: ", env.GCP_PRIVATE_KEY ? 
        `Set (length: ${env.GCP_PRIVATE_KEY.length} chars)` : "Missing");
    }

    if (url.pathname === "/api/upload") {
      if (request.method !== "POST") {
        return new Response("Method not allowed", { status: 405 });
      }
      
      try {
        const formData = await request.formData();
        const file = formData.get("file");
        
        if (!file) {
          return Response.json({ error: "No file provided" }, { status: 400 });
        }
        
        const contentType = file.type || "application/octet-stream";
        const fileName = formData.get("fileName") || file.name || "unknown-file";
        
        // Initialize performance data structure
        const responseData = {
          success: true,
          performance: {}
        };
        
        // Upload to R2 with performance measurement
        const r2StartTime = Date.now();
        const r2Key = `r2-${fileName}`;
        const r2Object = await env.R2_BUCKET.put(r2Key, file, {
          httpMetadata: {
            contentType: contentType
          },
          customMetadata: {
            uploadSource: "browser",
            originalFileName: fileName,
            appVersion: "1.0.0"
          }
        });
        
        // Get R2 metadata
        const r2Metadata = await env.R2_BUCKET.head(r2Key);
        const r2EndTime = Date.now();
        const r2UploadTime = r2EndTime - r2StartTime;
        
        // Add R2 data to response
        responseData.r2 = {
          key: r2Key,
          etag: r2Object.etag,
          size: r2Object.size,
          metadata: {
            contentType: r2Metadata.httpMetadata.contentType,
            etag: r2Metadata.etag,
            uploaded: r2Metadata.uploaded.toISOString(),
            version: r2Metadata.version || "Not available",
            customMetadata: r2Metadata.customMetadata || {}
          }
        };
        
        // Add R2 performance data
        responseData.performance.r2 = {
          uploadTimeMs: r2UploadTime,
          speedMBps: (r2Object.size / (1024 * 1024)) / (r2UploadTime / 1000),
          provider: "Cloudflare R2"
        };
        
        // Try GCS upload if credentials are available
        if (env.GCP_PROJECT_ID && env.GCP_CLIENT_EMAIL && env.GCP_PRIVATE_KEY && env.GCP_BUCKET_NAME) {
          try {
            // Measure GCS upload performance
            const gcsStartTime = Date.now();
            const gcsData = await uploadToGCS(env, file, fileName, contentType);
            const gcsEndTime = Date.now();
            const gcsUploadTime = gcsEndTime - gcsStartTime;
            
            // Add GCS data to response
            responseData.gcs = gcsData;
            
            // Add GCS performance data
            responseData.performance.gcs = {
              uploadTimeMs: gcsUploadTime,
              speedMBps: (gcsData.size / (1024 * 1024)) / (gcsUploadTime / 1000),
              provider: "Google Cloud Storage"
            };
          } catch (gcsError) {
            console.error("GCS error:", gcsError);
            // Include error info but don't fail the request
            responseData.gcsError = gcsError.message;
          }
        }
        
        // Try S3 upload if credentials are available
        if (env.AWS_ACCESS_KEY_ID && env.AWS_SECRET_ACCESS_KEY && env.AWS_REGION && env.S3_BUCKET_NAME) {
          try {
            // Measure S3 upload performance
            const s3StartTime = Date.now();
            const s3Data = await uploadToS3(env, file, fileName, contentType);
            const s3EndTime = Date.now();
            const s3UploadTime = s3EndTime - s3StartTime;
            
            // Add S3 data to response
            responseData.s3 = s3Data;
            
            // Add performance data
            if (!responseData.performance) {
              responseData.performance = {};
            }
            
            responseData.performance.s3 = {
              uploadTimeMs: s3UploadTime,
              speedMBps: (s3Data.size / (1024 * 1024)) / (s3UploadTime / 1000),
              provider: "Amazon S3"
            };
            
            // After all providers have been processed, calculate which one was fastest
            // Only create summary if we have at least 2 providers for comparison
            const availableProviders = [];
            if (responseData.performance.r2) availableProviders.push(['r2', responseData.performance.r2]);
            if (responseData.performance.gcs) availableProviders.push(['gcs', responseData.performance.gcs]);
            if (responseData.performance.s3) availableProviders.push(['s3', responseData.performance.s3]);
            
            if (availableProviders.length > 1) {
              if (!responseData.performance.summary) {
                responseData.performance.summary = { 
                  fastest: null,
                  comparison: {}
                };
              }
              
              // Find the fastest provider using the pre-filtered availableProviders
              const providers = availableProviders
                .sort(([, a], [, b]) => a.uploadTimeMs - b.uploadTimeMs);
              
              if (providers.length > 0) {
                const [fastestCode, fastestData] = providers[0];
                responseData.performance.summary.fastest = {
                  code: fastestCode,
                  provider: fastestData.provider,
                  uploadTimeMs: fastestData.uploadTimeMs,
                  speedMBps: fastestData.speedMBps
                };
                
                // Calculate comparisons between providers
                for (let i = 1; i < providers.length; i++) {
                  const [slowerCode, slowerData] = providers[i];
                  const timeDifferenceMs = slowerData.uploadTimeMs - fastestData.uploadTimeMs;
                  const timesFaster = slowerData.uploadTimeMs / fastestData.uploadTimeMs;
                  const percentageFaster = `${((timesFaster - 1) * 100).toFixed(1)}% faster`;
                  
                  responseData.performance.summary.comparison[`${fastestCode} vs ${slowerCode}`] = {
                    timeDifferenceMs,
                    timesFaster: timesFaster.toFixed(2),
                    percentageFaster
                  };
                }
              }
            }
          } catch (s3Error) {
            console.error("S3 error:", s3Error);
            // Include error info but don't fail the request
            responseData.s3Error = s3Error.message;
          }
        }
        
        return Response.json(responseData);
      } catch (error) {
        return Response.json({ error: error.message }, { status: 500 });
      }
    } else if (url.pathname === "/api/metadata") {
      if (request.method !== "GET") {
        return new Response("Method not allowed", { status: 405 });
      }
      
      const fileName = url.searchParams.get("fileName");
      if (!fileName) {
        return Response.json({ error: "No fileName provided" }, { status: 400 });
      }
      
      try {
        // Initialize response data with performance tracking
        const responseData = {
          performance: {}
        };
        
        // Measure R2 metadata retrieval performance
        const r2StartTime = Date.now();
        const r2Key = `r2-${fileName}`;
        const r2Metadata = await env.R2_BUCKET.head(r2Key);
        const r2EndTime = Date.now();
        const r2ReadTime = r2EndTime - r2StartTime;
        
        if (!r2Metadata) {
          return Response.json({ 
            error: `File "${fileName}" not found. Please upload it first or check that the file name is correct.` 
          }, { status: 404 });
        }
        
        // Add R2 metadata to response
        responseData.r2 = {
          key: r2Key,
          size: r2Metadata.size,
          metadata: {
            contentType: r2Metadata.httpMetadata.contentType,
            etag: r2Metadata.etag,
            uploaded: r2Metadata.uploaded.toISOString(),
            version: r2Metadata.version || "Not available",
            customMetadata: r2Metadata.customMetadata || {}
          }
        };
        
        // Add R2 performance data
        responseData.performance.r2 = {
          readTimeMs: r2ReadTime,
          provider: "Cloudflare R2"
        };
        
        // Try to get GCS metadata if credentials are available
        if (env.GCP_PROJECT_ID && env.GCP_CLIENT_EMAIL && env.GCP_PRIVATE_KEY && env.GCP_BUCKET_NAME) {
          try {
            // Measure GCS metadata retrieval performance
            const gcsStartTime = Date.now();
            const gcsMetadata = await getGCSMetadata(env, fileName);
            const gcsEndTime = Date.now();
            const gcsReadTime = gcsEndTime - gcsStartTime;
            
            if (gcsMetadata) {
              // Add GCS metadata to response
              responseData.gcs = gcsMetadata;
              
              // Add GCS performance data
              responseData.performance.gcs = {
                readTimeMs: gcsReadTime,
                provider: "Google Cloud Storage"
              };
            }
          } catch (gcsError) {
            console.error("GCS metadata error:", gcsError);
            // Include error info but don't fail the request
            responseData.gcsError = gcsError.message;
          }
        }
        
        // Try to get S3 metadata if credentials are available
        if (env.AWS_ACCESS_KEY_ID && env.AWS_SECRET_ACCESS_KEY && env.AWS_REGION && env.S3_BUCKET_NAME) {
          try {
            // Measure S3 metadata retrieval performance
            const s3StartTime = Date.now();
            const s3Metadata = await getS3Metadata(env, fileName);
            const s3EndTime = Date.now();
            const s3ReadTime = s3EndTime - s3StartTime;
            
            if (s3Metadata) {
              responseData.s3 = s3Metadata;
              
              // Add performance data
              if (!responseData.performance) {
                responseData.performance = {};
              }
              
              responseData.performance.s3 = {
                readTimeMs: s3ReadTime,
                provider: "Amazon S3"
              };
              
              // After all providers have been processed, calculate which one was fastest
              const availableProviders = [];
              if (responseData.performance.r2) availableProviders.push(['r2', responseData.performance.r2]);
              if (responseData.performance.gcs) availableProviders.push(['gcs', responseData.performance.gcs]);
              if (responseData.performance.s3) availableProviders.push(['s3', responseData.performance.s3]);
              
              if (availableProviders.length > 1) {
                if (!responseData.performance.summary) {
                  responseData.performance.summary = { 
                    fastest: null,
                    comparison: {}
                  };
                }
                
                // Find the fastest provider
                const providers = availableProviders
                  .sort(([, a], [, b]) => a.readTimeMs - b.readTimeMs);
                
                if (providers.length > 0) {
                  const [fastestCode, fastestData] = providers[0];
                  responseData.performance.summary.fastest = {
                    code: fastestCode,
                    provider: fastestData.provider,
                    readTimeMs: fastestData.readTimeMs
                  };
                  
                  // Calculate comparisons between providers
                  for (let i = 1; i < providers.length; i++) {
                    const [slowerCode, slowerData] = providers[i];
                    const timeDifferenceMs = slowerData.readTimeMs - fastestData.readTimeMs;
                    const timesFaster = slowerData.readTimeMs / fastestData.readTimeMs;
                    const percentageFaster = `${((timesFaster - 1) * 100).toFixed(1)}% faster`;
                    
                    responseData.performance.summary.comparison[`${fastestCode} vs ${slowerCode}`] = {
                      timeDifferenceMs,
                      timesFaster: timesFaster.toFixed(2),
                      percentageFaster
                    };
                  }
                }
              }
            }
          } catch (s3Error) {
            console.error("S3 metadata error:", s3Error);
            // Include error info but don't fail the request
            responseData.s3Error = s3Error.message;
          }
        }
        
        return Response.json(responseData);
      } catch (error) {
        return Response.json({ error: error.message }, { status: 500 });
      }
    } else if (url.pathname === "/api/list-objects") {
      // Endpoint to list available objects across all storage providers
      try {
        // Initialize result object
        const result = {
          r2: [],
          gcs: [],
          s3: []
        };
        
        // Get R2 objects (always available since it's required)
        try {
          const r2Objects = await env.R2_BUCKET.list({
            prefix: "r2-",
            limit: 50
          });
          
          // Format R2 objects
          result.r2 = r2Objects.objects.map(obj => ({
            key: obj.key,
            fileName: obj.key.replace('r2-', ''),
            size: obj.size,
            uploaded: obj.uploaded.toISOString(),
            etag: obj.etag
          }));
        } catch (r2Error) {
          console.error("Error listing R2 objects:", r2Error);
          result.r2Error = r2Error.message;
        }
        
        // Get GCS objects if credentials are available
        if (env.GCP_PROJECT_ID && env.GCP_CLIENT_EMAIL && env.GCP_PRIVATE_KEY && env.GCP_BUCKET_NAME) {
          try {
            // Get an access token for GCS
            const accessToken = await getGCSAccessToken(env);
            
            // List objects in the GCS bucket
            const response = await fetch(
              `https://storage.googleapis.com/storage/v1/b/${env.GCP_BUCKET_NAME}/o?prefix=gcs-`,
              {
                headers: {
                  "Authorization": `Bearer ${accessToken}`
                }
              }
            );
            
            if (!response.ok) {
              throw new Error(`GCS list operation failed: ${response.status}`);
            }
            
            const data = await response.json();
            
            // Format GCS objects
            if (data.items && Array.isArray(data.items)) {
              result.gcs = data.items.map(item => ({
                key: item.name,
                fileName: item.name.replace('gcs-', ''),
                size: parseInt(item.size, 10),
                uploaded: item.timeCreated,
                generation: item.generation
              }));
            }
          } catch (gcsError) {
            console.error("Error listing GCS objects:", gcsError);
            result.gcsError = gcsError.message;
          }
        }
        
        // Get S3 objects if credentials are available
        if (env.AWS_ACCESS_KEY_ID && env.AWS_SECRET_ACCESS_KEY && env.AWS_REGION && env.S3_BUCKET_NAME) {
          try {
            // Use our S3 signing process to list objects
            const bucketName = env.S3_BUCKET_NAME;
            const region = env.AWS_REGION;
            
            // Fixing URL format - using the virtual-hosted-style which is preferred
            const host = `${bucketName}.s3.${region}.amazonaws.com`;
            const path = `/`;
            
            // Using proper query parameter format for S3
            // The order of query parameters is important for the signature calculation
            const queryParams = "list-type=2&max-keys=100&prefix=s3-";
            
            console.log("S3 listing URL:", `https://${host}${path}?${queryParams}`);
            
            // Generate precise timestamp
            const amzDate = getAmzDate();
            const dateStamp = amzDate.slice(0, 8);
            
            // Set up authentication headers (explicit lowercase for canonical form)
            const headers = {
              "host": host,
              "x-amz-date": amzDate,
              "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            };
            
            // Sort and join header keys for signing
            const signedHeaders = Object.keys(headers).sort().join(";");
            
            // Construct canonical headers with precise format
            const canonicalHeaders = Object.keys(headers)
              .sort()
              .map(key => `${key.toLowerCase()}:${headers[key].trim()}`)
              .join('\n') + '\n';
            
            // Create canonical request with precise spacing and newlines
            const canonicalRequest = [
              "GET",
              path,
              queryParams,
              canonicalHeaders,
              signedHeaders,
              headers["x-amz-content-sha256"]
            ].join("\n");
            
            console.log("Canonical Request:", canonicalRequest);
            
            // Generate signing key
            const signingKey = await getSigningKey(
              env.AWS_SECRET_ACCESS_KEY,
              dateStamp,
              region,
              "s3"
            );
            
            // Hash the canonical request with sha256
            const requestHash = await sha256Hex(canonicalRequest);
            
            // Create string to sign with correct format
            const algorithm = "AWS4-HMAC-SHA256";
            const credentialScope = `${dateStamp}/${region}/s3/aws4_request`;
            
            const stringToSign = [
              algorithm,
              amzDate,
              credentialScope,
              requestHash
            ].join("\n");
            
            console.log("String to Sign:", stringToSign);
            
            // Calculate signature
            const signature = await hmacHex(signingKey, stringToSign);
            
            // Create authorization header
            const authorizationHeader = `${algorithm} Credential=${env.AWS_ACCESS_KEY_ID}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
            
            // Prepare headers for the request (uppercase for standard HTTP)
            const requestHeaders = {
              "Host": host,
              "X-Amz-Date": amzDate,
              "X-Amz-Content-Sha256": headers["x-amz-content-sha256"],
              "Authorization": authorizationHeader
            };
            
            console.log("Request Headers:", JSON.stringify(requestHeaders));
            
            // Make the request
            const response = await fetch(`https://${host}${path}?${queryParams}`, {
              method: "GET",
              headers: requestHeaders
            });
            
            console.log("S3 List Response Status:", response.status);
            
            if (!response.ok) {
              const errorText = await response.text();
              console.error(`S3 list operation failed: ${response.status}`, errorText);
              throw new Error(`S3 list operation failed: ${response.status} - ${errorText}`);
            }
            
            // Parse XML response
            const xml = await response.text();
            console.log("S3 list response XML:", xml.substring(0, 500) + "..."); // Log a preview of the XML
            
            // Initialize arrays
            const keys = [];
            const sizes = [];
            const dates = [];
            
            try {
              // Check for common error messages in the XML response
              if (xml.includes("<Error>")) {
                const errorCodeMatch = xml.match(/<Code>(.*?)<\/Code>/);
                const errorMessageMatch = xml.match(/<Message>(.*?)<\/Message>/);
                const errorCode = errorCodeMatch ? errorCodeMatch[1] : "Unknown error code";
                const errorMessage = errorMessageMatch ? errorMessageMatch[1] : "Unknown error message";
                
                console.error(`S3 returned XML error: ${errorCode} - ${errorMessage}`);
                throw new Error(`S3 API error: ${errorCode} - ${errorMessage}`);
              }
              
              // Try different XML patterns - S3 can return XML in slightly different formats
              let contentMatches = xml.match(/<Contents>[\s\S]*?<\/Contents>/g) || [];
              
              // If no Contents found, try alternative format
              if (contentMatches.length === 0) {
                // Try alternative XML format without the Contents tags
                const keyMatches = xml.match(/<Key>(.*?)<\/Key>/g) || [];
                console.log(`Found ${keyMatches.length} direct key matches in S3 response`);
                
                keyMatches.forEach(match => {
                  const key = match.replace('<Key>', '').replace('</Key>', '');
                  if (key.startsWith('s3-')) {
                    keys.push(key);
                    sizes.push(0); // Default size
                    dates.push(null); // Default date
                  }
                });
              } else {
                // Process structured Content elements
                console.log(`Found ${contentMatches.length} S3 objects in response`);
                
                // Process each Content element
                contentMatches.forEach(content => {
                  // Extract key
                  const keyMatch = content.match(/<Key>(.*?)<\/Key>/);
                  if (keyMatch && keyMatch[1]) {
                    const key = keyMatch[1];
                    console.log("Found S3 key:", key);
                    
                    // Only include keys with our prefix
                    if (key.startsWith('s3-')) {
                      keys.push(key);
                      
                      // Extract size from this content block
                      const sizeMatch = content.match(/<Size>(.*?)<\/Size>/);
                      if (sizeMatch && sizeMatch[1]) {
                        sizes.push(parseInt(sizeMatch[1], 10));
                      } else {
                        sizes.push(0);
                      }
                      
                      // Extract last modified date from this content block
                      const dateMatch = content.match(/<LastModified>(.*?)<\/LastModified>/);
                      if (dateMatch && dateMatch[1]) {
                        dates.push(dateMatch[1]);
                      } else {
                        dates.push(null);
                      }
                    }
                  }
                });
              }
            } catch (parseError) {
              console.error("Error parsing S3 XML response:", parseError);
              console.log("Raw XML response:", xml);
            }
            
            console.log(`Extracted ${keys.length} S3 objects with 's3-' prefix`);
            
            // Create S3 objects array
            for (let i = 0; i < keys.length; i++) {
              result.s3.push({
                key: keys[i],
                fileName: keys[i].replace('s3-', ''),
                size: i < sizes.length ? sizes[i] : 0,
                lastModified: i < dates.length ? dates[i] : null
              });
            }
            
            console.log("Final S3 objects list:", JSON.stringify(result.s3));
          } catch (s3Error) {
            console.error("Error listing S3 objects:", s3Error);
            result.s3Error = s3Error.message;
          }
        }
        
        // Create aggregated view for convenience
        const allFiles = new Map();
        
        // Add R2 files to the map
        result.r2.forEach(obj => {
          if (!allFiles.has(obj.fileName)) {
            allFiles.set(obj.fileName, { fileName: obj.fileName, providers: [] });
          }
          allFiles.get(obj.fileName).providers.push('r2');
        });
        
        // Add GCS files
        result.gcs.forEach(obj => {
          if (!allFiles.has(obj.fileName)) {
            allFiles.set(obj.fileName, { fileName: obj.fileName, providers: [] });
          }
          allFiles.get(obj.fileName).providers.push('gcs');
        });
        
        // Add S3 files
        result.s3.forEach(obj => {
          if (!allFiles.has(obj.fileName)) {
            allFiles.set(obj.fileName, { fileName: obj.fileName, providers: [] });
          }
          allFiles.get(obj.fileName).providers.push('s3');
        });
        
        // Log info if S3 listing operation fails
        if (result.s3.length === 0 && result.s3Error && env.AWS_ACCESS_KEY_ID) {
          console.log("S3 list operation failed:", result.s3Error);
          console.log("Please check S3 bucket permissions and ensure LIST operations are allowed");
        }
        
        // Convert the map to an array and add to the result
        result.files = Array.from(allFiles.values());
        
        // Include helpful metadata about the file verification process
        result.stats = {
          totalFiles: result.files.length,
          providerCounts: {
            r2: result.r2.length,
            gcs: result.gcs.length,
            s3: result.s3.length
          }
        };
        
        return Response.json(result);
      } catch (error) {
        return Response.json({ error: error.message }, { status: 500 });
      }
    } else if (url.pathname === "/api/status") {
      let storageProviders = ["R2"];
      let message = "Connected to R2";
      
      // Check GCS connectivity
      if (env.GCP_PROJECT_ID && env.GCP_CLIENT_EMAIL && env.GCP_PRIVATE_KEY && env.GCP_BUCKET_NAME) {
        storageProviders.push("GCS");
        message += " and GCS";
      }
      
      // Check S3 connectivity
      if (env.AWS_ACCESS_KEY_ID && env.AWS_SECRET_ACCESS_KEY && env.AWS_REGION && env.S3_BUCKET_NAME) {
        storageProviders.push("S3");
        message += " and S3";
      }
      
      return Response.json({
        status: "active",
        service: "storage-comparison-tool",
        storageProviders: storageProviders,
        message: message + ". Ready to compare cloud storage services."
      });
    } else if (url.pathname.startsWith("/api/")) {
      return Response.json({
        name: "Cloudflare Storage Comparison",
        version: "1.0.0",
        providers: ["R2", "GCS", "S3"],
        capabilities: ["file uploads", "metadata comparison", "content-type inference"]
      });
    }

    return new Response(null, { status: 404 });
  },
}