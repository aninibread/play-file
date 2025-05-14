import { useState, useRef, useEffect } from 'react'
import './App.css'

function App() {
  const [file, setFile] = useState(null)
  const [fileName, setFileName] = useState('')
  const [uploadResult, setUploadResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [metadata, setMetadata] = useState(null)
  const [resultTab, setResultTab] = useState('summary')
  const [metadataTab, setMetadataTab] = useState('r2')
  const fileInputRef = useRef(null)
  
  // Initialize tabs when data changes
  useEffect(() => {
    if (uploadResult) {
      // Added 'performance' tab for speed test results
      setResultTab(uploadResult.performance ? 'performance' : 'summary')
    }
    
    if (metadata) {
      // If there's performance data, set the tab to show it first
      if (metadata.performance && Object.keys(metadata.performance).length > 1) {
        setMetadataTab('performance')
      } else if (metadata.r2) {
        setMetadataTab('r2')
      } else if (metadata.gcs || metadata.gcsError) {
        setMetadataTab('gcs')
      } else if (metadata.s3 || metadata.s3Error) {
        setMetadataTab('s3')
      }
    }
  }, [uploadResult, metadata])

  const handleFileChange = (e) => {
    if (e.target.files.length > 0) {
      const selectedFile = e.target.files[0]
      setFile(selectedFile)
      setFileName(selectedFile.name)
    }
  }

  const handleUpload = async () => {
    if (!file) {
      setError('Please select a file first')
      return
    }

    // Hide metadata results when showing upload results to avoid UI clutter
    setMetadata(null)
    
    setLoading(true)
    setError(null)
    setUploadResult(null)

    try {
      const formData = new FormData()
      formData.append('file', file)
      formData.append('fileName', fileName)

      const response = await fetch('/api/upload', {
        method: 'POST',
        body: formData
      })

      if (!response.ok) {
        throw new Error(`Upload failed: ${response.statusText}`)
      }

      const result = await response.json()
      setUploadResult(result)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const fetchMetadata = async () => {
    if (!fileName) {
      setError('Please provide a file name')
      return
    }

    // Hide upload results when showing metadata to avoid UI clutter
    setUploadResult(null)
    
    setLoading(true)
    setError(null)
    setMetadata(null)

    try {
      const response = await fetch(`/api/metadata?fileName=${encodeURIComponent(fileName)}`)
      
      const data = await response.json()
      
      if (!response.ok) {
        throw new Error(data.error || `Failed to fetch metadata: ${response.statusText}`)
      }

      setMetadata(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const resetForm = () => {
    setFile(null)
    setFileName('')
    setUploadResult(null)
    setMetadata(null)
    setError(null)
    if (fileInputRef.current) {
      fileInputRef.current.value = ''
    }
  }

  return (
    <>
      <h1>Storage Provider Comparison Tool</h1>
      
      <div className='card'>
        <h2>Upload File to Cloud Storage</h2>
        <div className="form-group">
          <input 
            type="file" 
            onChange={handleFileChange} 
            ref={fileInputRef}
            className="file-input"
          />
          <input
            type="text"
            value={fileName}
            onChange={(e) => setFileName(e.target.value)}
            placeholder="File name (optional)"
            className="text-input"
          />
        </div>
        
        <div className="buttons">
          <button 
            onClick={handleUpload} 
            disabled={loading || !file}
            className="button primary"
          >
            {loading ? 'Uploading...' : 'Upload File'}
          </button>
          
          <button 
            onClick={fetchMetadata} 
            disabled={loading || !fileName}
            className="button secondary"
          >
            Get Metadata
          </button>
          
          <button 
            onClick={resetForm}
            className="button outline"
          >
            Reset
          </button>
        </div>
        
        {error && (
          <div className="error-message">
            <p>{error}</p>
            {error.includes("not found") && (
              <p className="suggestion">
                Try uploading a file first, then use "Get Metadata" to retrieve its information.
              </p>
            )}
          </div>
        )}
        
        {uploadResult && (
          <div className="result-section">
            <h3>Upload Result</h3>
            <div className="provider-tabs">
              <div className="tab-buttons">
                {uploadResult.performance && (
                  <button 
                    className={`tab-button ${resultTab === 'performance' ? 'active' : ''}`}
                    onClick={() => setResultTab('performance')}
                  >
                    Performance
                  </button>
                )}
                <button 
                  className={`tab-button ${resultTab === 'summary' ? 'active' : ''}`}
                  onClick={() => setResultTab('summary')}
                >
                  Summary
                </button>
                {uploadResult.r2 && (
                  <button 
                    className={`tab-button ${resultTab === 'r2' ? 'active' : ''}`}
                    onClick={() => setResultTab('r2')}
                  >
                    R2
                  </button>
                )}
                {(uploadResult.gcs || uploadResult.gcsError) && (
                  <button 
                    className={`tab-button ${resultTab === 'gcs' ? 'active' : ''}`}
                    onClick={() => setResultTab('gcs')}
                  >
                    GCS
                  </button>
                )}
                {(uploadResult.s3 || uploadResult.s3Error) && (
                  <button 
                    className={`tab-button ${resultTab === 's3' ? 'active' : ''}`}
                    onClick={() => setResultTab('s3')}
                  >
                    S3
                  </button>
                )}
              </div>
              
              <div className="tab-content">
                {resultTab === 'performance' && uploadResult.performance && (
                  <div className="performance-view">
                    <h4>Upload Performance</h4>
                    
                    {/* Provider Speed Comparison */}
                    <div className="speed-comparison">
                      <h5>Upload Speed Test Results</h5>
                      <table className="metadata-table">
                        <thead>
                          <tr>
                            <th>Provider</th>
                            <th>Upload Time</th>
                            <th>Speed</th>
                          </tr>
                        </thead>
                        <tbody>
                          {uploadResult.performance.r2 && (
                            <tr className={uploadResult.performance.summary?.fastest?.code === 'r2' ? 'fastest-provider' : ''}>
                              <td>{uploadResult.performance.r2.provider}</td>
                              <td>{uploadResult.performance.r2.uploadTimeMs} ms</td>
                              <td>{uploadResult.performance.r2.speedMBps.toFixed(2)} MB/s</td>
                            </tr>
                          )}
                          {uploadResult.performance.gcs && (
                            <tr className={uploadResult.performance.summary?.fastest?.code === 'gcs' ? 'fastest-provider' : ''}>
                              <td>{uploadResult.performance.gcs.provider}</td>
                              <td>{uploadResult.performance.gcs.uploadTimeMs} ms</td>
                              <td>{uploadResult.performance.gcs.speedMBps.toFixed(2)} MB/s</td>
                            </tr>
                          )}
                          {uploadResult.performance.s3 && (
                            <tr className={uploadResult.performance.summary?.fastest?.code === 's3' ? 'fastest-provider' : ''}>
                              <td>{uploadResult.performance.s3.provider}</td>
                              <td>{uploadResult.performance.s3.uploadTimeMs} ms</td>
                              <td>{uploadResult.performance.s3.speedMBps.toFixed(2)} MB/s</td>
                            </tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                    
                    {/* Fastest Provider */}
                    {uploadResult.performance.summary?.fastest && (
                      <div className="fastest-provider-info">
                        <h5>Fastest Provider</h5>
                        <div className="info-box">
                          <div className="fastest-header">
                            <strong>{uploadResult.performance.summary.fastest.provider}</strong> 
                            <span> was fastest with {uploadResult.performance.summary.fastest.uploadTimeMs} ms upload time</span>
                          </div>
                          <div className="upload-speed">
                            Speed: {uploadResult.performance.summary.fastest.speedMBps.toFixed(2)} MB/s
                          </div>
                        </div>
                      </div>
                    )}
                    
                    {/* Detailed Comparison */}
                    {uploadResult.performance.summary?.comparison && 
                     Object.keys(uploadResult.performance.summary.comparison).length > 0 && (
                      <div className="comparison-data">
                        <h5>Detailed Speed Comparison</h5>
                        <table className="metadata-table">
                          <thead>
                            <tr>
                              <th>Comparison</th>
                              <th>Time Difference</th>
                              <th>Times Faster</th>
                            </tr>
                          </thead>
                          <tbody>
                            {Object.entries(uploadResult.performance.summary.comparison).map(([key, value]) => (
                              <tr key={key}>
                                <td>{key}</td>
                                <td>{value.timeDifferenceMs} ms</td>
                                <td>{value.timesFaster}x ({value.percentageFaster})</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                )}
                
                {resultTab === 'summary' && (
                  <div className="summary-view">
                    <table className="metadata-table">
                    <thead>
                      <tr>
                        <th>Property</th>
                        {uploadResult.r2 && <th>R2</th>}
                        {uploadResult.gcs && <th>GCS</th>}
                        {uploadResult.s3 && <th>S3</th>}
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <td>Object Key</td>
                        {uploadResult.r2 && <td>{uploadResult.r2.key}</td>}
                        {uploadResult.gcs && <td>{uploadResult.gcs.key}</td>}
                        {uploadResult.s3 && <td>{uploadResult.s3.key}</td>}
                      </tr>
                      <tr>
                        <td>Size</td>
                        {uploadResult.r2 && <td>{uploadResult.r2.size} bytes</td>}
                        {uploadResult.gcs && <td>{uploadResult.gcs.size} bytes</td>}
                        {uploadResult.s3 && <td>{uploadResult.s3.size} bytes</td>}
                      </tr>
                      <tr>
                        <td>Content Type</td>
                        {uploadResult.r2 && <td>{uploadResult.r2.metadata.contentType}</td>}
                        {uploadResult.gcs && <td>{uploadResult.gcs.metadata.contentType}</td>}
                        {uploadResult.s3 && <td>{uploadResult.s3.metadata.contentType}</td>}
                      </tr>
                      <tr>
                        <td>ETag</td>
                        {uploadResult.r2 && <td>{uploadResult.r2.etag}</td>}
                        {uploadResult.gcs && <td>{uploadResult.gcs.etag}</td>}
                        {uploadResult.s3 && <td>{uploadResult.s3.etag}</td>}
                      </tr>
                      <tr>
                        <td>Created/Uploaded</td>
                        {uploadResult.r2 && <td>{uploadResult.r2.metadata.uploaded}</td>}
                        {uploadResult.gcs && <td>{uploadResult.gcs.metadata.timeCreated}</td>}
                        {uploadResult.s3 && <td>{uploadResult.s3.metadata.lastModified}</td>}
                      </tr>
                    </tbody>
                  </table>
                </div>
                )}

                {resultTab === 'r2' && uploadResult.r2 && (
                  <div className="r2-result">
                    <h4>R2 Upload Details</h4>
                    <table className="metadata-table">
                      <tbody>
                        <tr>
                          <td>Object Key</td>
                          <td>{uploadResult.r2.key}</td>
                        </tr>
                        <tr>
                          <td>Size</td>
                          <td>{uploadResult.r2.size} bytes</td>
                        </tr>
                        <tr>
                          <td>ETag</td>
                          <td>{uploadResult.r2.etag}</td>
                        </tr>
                        <tr>
                          <td>Content Type</td>
                          <td>{uploadResult.r2.metadata.contentType}</td>
                        </tr>
                        <tr>
                          <td>Uploaded</td>
                          <td>{uploadResult.r2.metadata.uploaded}</td>
                        </tr>
                        <tr>
                          <td>Version</td>
                          <td>{uploadResult.r2.metadata.version || "Not available"}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                )}

                {resultTab === 'gcs' && (
                  <div className="gcs-result">
                    <h4>GCS Upload Details</h4>
                    {uploadResult.gcsError ? (
                      <p className="error-message">Error: {uploadResult.gcsError}</p>
                    ) : !uploadResult.gcs ? (
                      <p className="info-note">No GCS data available.</p>
                    ) : (
                    <table className="metadata-table">
                      <tbody>
                        <tr>
                          <td>Object Key</td>
                          <td>{uploadResult.gcs.key}</td>
                        </tr>
                        <tr>
                          <td>Size</td>
                          <td>{uploadResult.gcs.size} bytes</td>
                        </tr>
                        <tr>
                          <td>ETag</td>
                          <td>{uploadResult.gcs.etag}</td>
                        </tr>
                        <tr>
                          <td>Content Type</td>
                          <td>{uploadResult.gcs.metadata.contentType}</td>
                        </tr>
                        <tr>
                          <td>Time Created</td>
                          <td>{uploadResult.gcs.metadata.timeCreated}</td>
                        </tr>
                        <tr>
                          <td>Updated</td>
                          <td>{uploadResult.gcs.metadata.updated}</td>
                        </tr>
                        <tr>
                          <td>Generation</td>
                          <td>{uploadResult.gcs.metadata.generation}</td>
                        </tr>
                        <tr>
                          <td>MD5 Hash</td>
                          <td>{uploadResult.gcs.metadata.md5Hash}</td>
                        </tr>
                        <tr>
                          <td>CRC32C</td>
                          <td>{uploadResult.gcs.metadata.crc32c}</td>
                        </tr>
                      </tbody>
                    </table>
                    )}
                  </div>
                )}
                
                {resultTab === 's3' && (
                  <div className="s3-result">
                    <h4>S3 Upload Details</h4>
                    {uploadResult.s3Error ? (
                      <p className="error-message">Error: {uploadResult.s3Error}</p>
                    ) : !uploadResult.s3 ? (
                      <p className="info-note">No S3 data available.</p>
                    ) : (
                    <table className="metadata-table">
                      <tbody>
                        <tr>
                          <td>Object Key</td>
                          <td>{uploadResult.s3.key}</td>
                        </tr>
                        <tr>
                          <td>Size</td>
                          <td>{uploadResult.s3.size} bytes</td>
                        </tr>
                        <tr>
                          <td>ETag</td>
                          <td>{uploadResult.s3.etag}</td>
                        </tr>
                        <tr>
                          <td>Content Type</td>
                          <td>{uploadResult.s3.metadata.contentType}</td>
                        </tr>
                        <tr>
                          <td>Last Modified</td>
                          <td>{uploadResult.s3.metadata.lastModified}</td>
                        </tr>
                        <tr>
                          <td>Version ID</td>
                          <td>{uploadResult.s3.metadata.versionId}</td>
                        </tr>
                        {uploadResult.s3.metadata.contentMD5 && (
                          <tr>
                            <td>Content MD5</td>
                            <td>{uploadResult.s3.metadata.contentMD5}</td>
                          </tr>
                        )}
                        {uploadResult.s3.metadata.storageClass && (
                          <tr>
                            <td>Storage Class</td>
                            <td>{uploadResult.s3.metadata.storageClass}</td>
                          </tr>
                        )}
                        {uploadResult.s3.metadata.serverSideEncryption && (
                          <tr>
                            <td>Server-Side Encryption</td>
                            <td>{uploadResult.s3.metadata.serverSideEncryption}</td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                    )}
                  </div>
                )}
              </div>
            </div>
            <details>
              <summary>Raw JSON Response</summary>
              <pre>{JSON.stringify(uploadResult, null, 2)}</pre>
            </details>
          </div>
        )}
        
        {metadata && (
          <div className="result-section">
            <h3>File Metadata</h3>
            <div className="provider-tabs">
              <div className="tab-buttons">
                {metadata.performance && (
                  <button 
                    className={`tab-button ${metadataTab === 'performance' ? 'active' : ''}`}
                    onClick={() => setMetadataTab('performance')}
                  >
                    Performance
                  </button>
                )}
                {metadata.r2 && (
                  <button 
                    className={`tab-button ${metadataTab === 'r2' ? 'active' : ''}`}
                    onClick={() => setMetadataTab('r2')}
                  >
                    R2
                  </button>
                )}
                {(metadata.gcs || metadata.gcsError) && (
                  <button 
                    className={`tab-button ${metadataTab === 'gcs' ? 'active' : ''}`}
                    onClick={() => setMetadataTab('gcs')}
                  >
                    GCS
                  </button>
                )}
                {(metadata.s3 || metadata.s3Error) && (
                  <button 
                    className={`tab-button ${metadataTab === 's3' ? 'active' : ''}`}
                    onClick={() => setMetadataTab('s3')}
                  >
                    S3
                  </button>
                )}
              </div>
              
              <div className="tab-content">
                {metadataTab === 'performance' && metadata.performance && (
                  <div className="performance-view">
                    <h4>Metadata Retrieval Performance</h4>
                    
                    {/* Provider Speed Comparison */}
                    <div className="speed-comparison">
                      <h5>Retrieval Speed Test Results</h5>
                      <table className="metadata-table">
                        <thead>
                          <tr>
                            <th>Provider</th>
                            <th>Read Time</th>
                          </tr>
                        </thead>
                        <tbody>
                          {metadata.performance.r2 && (
                            <tr className={metadata.performance.summary?.fastest?.code === 'r2' ? 'fastest-provider' : ''}>
                              <td>{metadata.performance.r2.provider}</td>
                              <td>{metadata.performance.r2.readTimeMs} ms</td>
                            </tr>
                          )}
                          {metadata.performance.gcs && (
                            <tr className={metadata.performance.summary?.fastest?.code === 'gcs' ? 'fastest-provider' : ''}>
                              <td>{metadata.performance.gcs.provider}</td>
                              <td>{metadata.performance.gcs.readTimeMs} ms</td>
                            </tr>
                          )}
                          {metadata.performance.s3 && (
                            <tr className={metadata.performance.summary?.fastest?.code === 's3' ? 'fastest-provider' : ''}>
                              <td>{metadata.performance.s3.provider}</td>
                              <td>{metadata.performance.s3.readTimeMs} ms</td>
                            </tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                    
                    {/* Fastest Provider */}
                    {metadata.performance.summary?.fastest && (
                      <div className="fastest-provider-info">
                        <h5>Fastest Provider</h5>
                        <div className="info-box">
                          <div className="fastest-header">
                            <strong>{metadata.performance.summary.fastest.provider}</strong> 
                            <span> was fastest with {metadata.performance.summary.fastest.readTimeMs} ms retrieval time</span>
                          </div>
                        </div>
                      </div>
                    )}
                    
                    {/* Detailed Comparison */}
                    {metadata.performance.summary?.comparison && 
                     Object.keys(metadata.performance.summary.comparison).length > 0 && (
                      <div className="comparison-data">
                        <h5>Detailed Speed Comparison</h5>
                        <table className="metadata-table">
                          <thead>
                            <tr>
                              <th>Comparison</th>
                              <th>Time Difference</th>
                              <th>Times Faster</th>
                            </tr>
                          </thead>
                          <tbody>
                            {Object.entries(metadata.performance.summary.comparison).map(([key, value]) => (
                              <tr key={key}>
                                <td>{key}</td>
                                <td>{value.timeDifferenceMs} ms</td>
                                <td>{value.timesFaster}x ({value.percentageFaster})</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                )}
                
                {metadataTab === 'r2' && metadata.r2 && (
                  <div className="r2-metadata">
                    <h4>R2 Metadata</h4>
                    <table className="metadata-table">
                      <tbody>
                        <tr>
                          <td>Key</td>
                          <td>{metadata.r2.key}</td>
                        </tr>
                        <tr>
                          <td>Size</td>
                          <td>{metadata.r2.size} bytes</td>
                        </tr>
                        <tr>
                          <td>Content Type</td>
                          <td>{metadata.r2.metadata.contentType}</td>
                        </tr>
                        <tr>
                          <td>ETag</td>
                          <td>{metadata.r2.metadata.etag}</td>
                        </tr>
                        <tr>
                          <td>Uploaded</td>
                          <td>{metadata.r2.metadata.uploaded}</td>
                        </tr>
                        {metadata.r2.metadata.version && (
                          <tr>
                            <td>Version</td>
                            <td>{metadata.r2.metadata.version}</td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                )}
                
                {metadataTab === 'gcs' && (
                  <div className="gcs-metadata">
                    <h4>GCS Metadata</h4>
                    {metadata.gcsError ? (
                      <p className="error-message">Error: {metadata.gcsError}</p>
                    ) : !metadata.gcs ? (
                      <p className="info-note">No GCS metadata available.</p>
                    ) : (
                    <table className="metadata-table">
                      <tbody>
                        <tr>
                          <td>Key</td>
                          <td>{metadata.gcs.key}</td>
                        </tr>
                        <tr>
                          <td>Size</td>
                          <td>{metadata.gcs.size} bytes</td>
                        </tr>
                        <tr>
                          <td>Content Type</td>
                          <td>{metadata.gcs.metadata.contentType}</td>
                        </tr>
                        <tr>
                          <td>ETag</td>
                          <td>{metadata.gcs.metadata.etag}</td>
                        </tr>
                        <tr>
                          <td>Created</td>
                          <td>{metadata.gcs.metadata.timeCreated}</td>
                        </tr>
                        <tr>
                          <td>Updated</td>
                          <td>{metadata.gcs.metadata.updated}</td>
                        </tr>
                        <tr>
                          <td>Generation</td>
                          <td>{metadata.gcs.metadata.generation}</td>
                        </tr>
                        <tr>
                          <td>MD5 Hash</td>
                          <td>{metadata.gcs.metadata.md5Hash}</td>
                        </tr>
                        <tr>
                          <td>CRC32C</td>
                          <td>{metadata.gcs.metadata.crc32c}</td>
                        </tr>
                      </tbody>
                    </table>
                    )}
                  </div>
                )}
                
                {metadataTab === 's3' && (
                  <div className="s3-metadata">
                    <h4>S3 Metadata</h4>
                    {metadata.s3Error ? (
                      <p className="error-message">Error: {metadata.s3Error}</p>
                    ) : !metadata.s3 ? (
                      <p className="info-note">No S3 metadata available.</p>
                    ) : (
                    <table className="metadata-table">
                      <tbody>
                        <tr>
                          <td>Key</td>
                          <td>{metadata.s3.key}</td>
                        </tr>
                        <tr>
                          <td>Size</td>
                          <td>{metadata.s3.size} bytes</td>
                        </tr>
                        <tr>
                          <td>Content Type</td>
                          <td>{metadata.s3.metadata.contentType}</td>
                        </tr>
                        <tr>
                          <td>ETag</td>
                          <td>{metadata.s3.metadata.etag}</td>
                        </tr>
                        <tr>
                          <td>Last Modified</td>
                          <td>{metadata.s3.metadata.lastModified}</td>
                        </tr>
                        <tr>
                          <td>Version ID</td>
                          <td>{metadata.s3.metadata.versionId}</td>
                        </tr>
                        {metadata.s3.metadata.contentMD5 && (
                          <tr>
                            <td>Content MD5</td>
                            <td>{metadata.s3.metadata.contentMD5}</td>
                          </tr>
                        )}
                        {metadata.s3.metadata.storageClass && (
                          <tr>
                            <td>Storage Class</td>
                            <td>{metadata.s3.metadata.storageClass}</td>
                          </tr>
                        )}
                        {metadata.s3.metadata.serverSideEncryption && (
                          <tr>
                            <td>Server-Side Encryption</td>
                            <td>{metadata.s3.metadata.serverSideEncryption}</td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                    )}
                  </div>
                )}
              </div>
            </div>
            <details>
              <summary>Raw JSON Response</summary>
              <pre>{JSON.stringify(metadata, null, 2)}</pre>
            </details>
          </div>
        )}
      </div>
      
      <p className='info-text'>
        This tool uploads files to multiple cloud storage providers (R2, GCS, S3) and compares their metadata handling,
        content-type inference, checksums, and versioning capabilities.
      </p>
    </>
  )
}

export default App
