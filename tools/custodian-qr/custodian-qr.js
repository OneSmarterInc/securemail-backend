// Bundled locally for the independent custodian page; never use a QR web service.
import QRCode from "qrcode";
window.renderCustodianQr = (canvas, uri) => QRCode.toCanvas(canvas, uri, { width: 224, margin: 2, errorCorrectionLevel: "M" });
