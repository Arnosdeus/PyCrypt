import React, { useState } from "react";
import "./App.css";

const API_BASE = "http://127.0.0.1:5000";

function timestampString() {
  const now = new Date();
  return now.toISOString().replace(/[:.-]/g, "").slice(0, 15);
}

export default function App() {
  const [file, setFile] = useState(null);
  const [method, setMethod] = useState("AES");
  const [key, setKey] = useState("");
  const [decryptionKey, setDecryptionKey] = useState("");
  const [showKey, setShowKey] = useState(false);
  const [loading, setLoading] = useState(false);

  const downloadBlob = (blob, filename) => {
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const saveKeyFile = (keyString) => {
    const ts = timestampString();
    const fileName = `${method}_key_${ts}.key`;
    const blob = new Blob([keyString], { type: "text/plain" });
    downloadBlob(blob, fileName);
  };

  const handleFileChange = (e) => setFile(e.target.files[0]);

  const handleEncrypt = async () => {
    if (!file) return alert("Choose a file first.");
    setLoading(true);
    try {
      const fd = new FormData();
      fd.append("file", file);
      fd.append("method", method);

      const res = await fetch(`${API_BASE}/encrypt`, { method: "POST", body: fd });
      if (!res.ok) throw new Error("Encryption failed");

      const headerKey =
        res.headers.get("X-Encryption-Key") || res.headers.get("x-encryption-key");
      const json = await res.json().catch(() => null);
      const returnedKey = headerKey || (json && json.key);
      if (!returnedKey) throw new Error("No encryption key received from server.");

      setKey(returnedKey);
      setShowKey(true);
      saveKeyFile(returnedKey);

      const filename = json?.filename || `${file.name}.encrypted`;
      const fileRes = await fetch(`${API_BASE}/download/${encodeURIComponent(filename)}`);
      if (!fileRes.ok) throw new Error("Failed to download encrypted file.");
      const blob = await fileRes.blob();
      downloadBlob(blob, filename);

      alert("✅ Encryption successful — key and file downloaded.");
    } catch (err) {
      console.error(err);
      alert("Encryption error: " + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleDecrypt = async () => {
    if (!file) return alert("Choose an encrypted file to decrypt.");
    const keyToUse = decryptionKey || key;
    if (!keyToUse) return alert("Please paste or upload a decryption key.");

    setLoading(true);
    try {
      const fd = new FormData();
      fd.append("file", file);
      fd.append("method", method);
      fd.append("key", keyToUse);

      const res = await fetch(`${API_BASE}/decrypt`, { method: "POST", body: fd });
      if (!res.ok) throw new Error("Decryption failed");

      const disposition = res.headers.get("content-disposition") || "";
      let filename = "decrypted_file";
      const match = disposition.match(/filename="?([^"]+)"?/);
      if (match && match[1]) filename = decodeURIComponent(match[1]);

      const blob = await res.blob();
      downloadBlob(blob, filename);
      alert("✅ Decryption successful — file downloaded: " + filename);
    } catch (err) {
      console.error(err);
      alert("Decryption error: " + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleCopyKey = async () => {
    if (!key) return alert("No key to copy.");
    try {
      await navigator.clipboard.writeText(key);
      alert("Key copied to clipboard.");
    } catch {
      alert("Failed to copy key.");
    }
  };

  const handleKeyFileUpload = (e) => {
    const uploaded = e.target.files[0];
    if (!uploaded) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const content = ev.target.result.trim();
      setDecryptionKey(content);
      alert("✅ Key file loaded successfully!");
    };
    reader.onerror = () => alert("Failed to read key file.");
    reader.readAsText(uploaded);
  };

  return (
    <div className="app-container">
      <h1>🔐 SecureScan Encryption Suite</h1>

      <div className="card">
        <label>Encryption Method</label>
        <select value={method} onChange={(e) => setMethod(e.target.value)}>
          <option value="AES">AES (AES-GCM)</option>
          <option value="Fernet">Fernet</option>
          <option value="RSA">RSA (Hybrid)</option>
        </select>

        <label>Choose File</label>
        <input type="file" onChange={handleFileChange} />

        <div className="button-row">
          <button onClick={handleEncrypt} disabled={loading}>
            {loading ? "Working..." : "Encrypt File"}
          </button>
          <button onClick={handleDecrypt} disabled={loading}>
            {loading ? "Working..." : "Decrypt File"}
          </button>
        </div>

        {showKey && (
          <div className="key-area">
            <label>Encryption Key (auto-generated)</label>
            <div className="key-row">
              <input type="text" value={key} readOnly />
              <button onClick={handleCopyKey}>Copy</button>
            </div>
          </div>
        )}

        <div className="key-area">
          <label>Paste or Upload Decryption Key</label>
          <input
            type="text"
            placeholder="Paste key here..."
            value={decryptionKey}
            onChange={(e) => setDecryptionKey(e.target.value)}
          />
          <input
            type="file"
            accept=".key"
            onChange={handleKeyFileUpload}
            style={{
              marginTop: "10px",
              background: "#0b1219",
              color: "#00ffc8",
              border: "1px dashed #00ffc8",
              padding: "8px",
              borderRadius: "6px",
            }}
          />
        </div>
      </div>
    </div>
  );
}
