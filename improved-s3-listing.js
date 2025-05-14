// S3 listing function - improved version
async function listS3Objects(env) {
  try {
    // Use our S3 signing process to list objects
    const bucketName = env.S3_BUCKET_NAME;
    const region = env.AWS_REGION;
    
    // Use path-style URL since it's more compatible with different S3 implementations
    const host = `s3.${region}.amazonaws.com`;
    const path = `/${bucketName}`;
    
    // Properly encode query parameters for S3 list objects V2
    const queryParams = new URLSearchParams({
      "list-type": "2",
      "prefix": "s3-",
      "max-keys": "100"
    }).toString();
    
    const url = `https://${host}${path}?${queryParams}`;
    console.log("S3 listing URL:", url);
    
    // Set up authentication headers with content-type
    const headers = {
      "host": host,
      "content-type": "application/x-www-form-urlencoded",
      "x-amz-date": getAmzDate(),
      "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    };
    
    // Get date components
    const amzDate = headers["x-amz-date"];
    const dateStamp = amzDate.slice(0, 8);
    
    // Generate signing key
    const signingKey = await getSigningKey(
      env.AWS_SECRET_ACCESS_KEY,
      dateStamp,
      region,
      "s3"
    );
    
    // Create canonical request
    const signedHeaders = Object.keys(headers).sort().join(";");
    
    // Using canonical URI (path) and canonical query string
    const canonicalUri = path;
    const canonicalQueryString = queryParams;
    
    // Construct canonical headers properly
    const canonicalHeaders = Object.keys(headers)
      .sort()
      .map(key => `${key.toLowerCase()}:${headers[key].trim()}`)
      .join('\n') + '\n';
    
    // Create canonical request directly (not using helper function)
    const canonicalRequest = [
      "GET",
      canonicalUri,
      canonicalQueryString,
      canonicalHeaders,
      signedHeaders,
      headers["x-amz-content-sha256"]
    ].join("\n");
    
    console.log("Canonical Request:", canonicalRequest);
    
    // Create string to sign directly
    const algorithm = "AWS4-HMAC-SHA256";
    const credentialScope = `${dateStamp}/${region}/s3/aws4_request`;
    const requestHash = await sha256Hex(canonicalRequest);
    
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
      "Content-Type": headers["content-type"],
      "X-Amz-Date": amzDate,
      "X-Amz-Content-Sha256": headers["x-amz-content-sha256"],
      "Authorization": authorizationHeader
    };
    
    console.log("Request Headers:", JSON.stringify(requestHeaders));
    
    // Make the request
    const response = await fetch(url, {
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
      // Check for error message
      if (xml.includes("<Error>")) {
        const errorCodeMatch = xml.match(/<Code>(.*?)<\/Code>/);
        const errorMessageMatch = xml.match(/<Message>(.*?)<\/Message>/);
        const errorCode = errorCodeMatch ? errorCodeMatch[1] : "Unknown error code";
        const errorMessage = errorMessageMatch ? errorMessageMatch[1] : "Unknown error message";
        
        console.error(`S3 returned XML error: ${errorCode} - ${errorMessage}`);
        throw new Error(`S3 API error: ${errorCode} - ${errorMessage}`);
      }
      
      // Extract all Content elements using more robust regex
      const contentsRegex = /<Contents>[\s\S]*?<\/Contents>/g;
      const contentMatches = xml.match(contentsRegex) || [];
      
      console.log(`Found ${contentMatches.length} content blocks in S3 response`);
      
      if (contentMatches.length === 0) {
        // If we have a ListBucketResult but no Contents, the bucket may be empty
        if (xml.includes("<ListBucketResult")) {
          console.log("Bucket appears to be empty (no Contents elements found)");
        } else {
          // Try to extract any Key elements from the response as a fallback
          const keyRegex = /<Key>([^<]+)<\/Key>/g;
          let keyMatch;
          
          while ((keyMatch = keyRegex.exec(xml)) !== null) {
            const key = keyMatch[1];
            if (key.startsWith('s3-')) {
              console.log("Found key via fallback:", key);
              keys.push(key);
              sizes.push(0); // Default size when we can't extract it
              dates.push(null); // Default date when we can't extract it
            }
          }
        }
      } else {
        // Extract data from each Contents block
        contentMatches.forEach(content => {
          // Extract key with more robust pattern
          const keyRegex = /<Key>([^<]+)<\/Key>/;
          const keyMatch = content.match(keyRegex);
          
          if (keyMatch && keyMatch[1]) {
            const key = keyMatch[1];
            
            // Only include keys with our prefix
            if (key.startsWith('s3-')) {
              console.log("Found S3 key:", key);
              keys.push(key);
              
              // Extract size with more robust pattern
              const sizeRegex = /<Size>(\d+)<\/Size>/;
              const sizeMatch = content.match(sizeRegex);
              sizes.push(sizeMatch ? parseInt(sizeMatch[1], 10) : 0);
              
              // Extract last modified with more robust pattern
              const dateRegex = /<LastModified>([^<]+)<\/LastModified>/;
              const dateMatch = content.match(dateRegex);
              dates.push(dateMatch ? dateMatch[1] : null);
            }
          }
        });
      }
    } catch (parseError) {
      console.error("Error parsing S3 XML response:", parseError);
      console.log("Raw XML response:", xml);
    }
    
    console.log(`Extracted ${keys.length} S3 objects with 's3-' prefix`);
    
    return { keys, sizes, dates };
  } catch (error) {
    console.error("Error listing S3 objects:", error);
    throw error;
  }
}