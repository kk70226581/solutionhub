const CHAT_IMAGE_MAX_BYTES = 2 * 1024 * 1024;
const CHAT_FILE_MAX_BYTES = 8 * 1024 * 1024;

const CHAT_DOCUMENT_MIME_TYPES = new Set([
  'application/pdf',
  'text/plain',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
]);

const CHAT_DOCUMENT_EXTENSIONS = ['.pdf', '.txt', '.doc', '.docx'];

export const CHAT_ATTACHMENT_ACCEPT =
  'image/*,audio/*,application/pdf,text/plain,.pdf,.txt,.doc,.docx,.mp3,.wav,.m4a,.ogg,.aac';

const hasDocumentExtension = (name = '') =>
  CHAT_DOCUMENT_EXTENSIONS.some((ext) => String(name || '').toLowerCase().endsWith(ext));

export const getChatAttachmentType = ({ mime = '', name = '', messageType = '', attachmentUrl = '', imageUrl = '' } = {}) => {
  const normalizedMime = String(mime || '').toLowerCase();
  const normalizedName = String(name || '').toLowerCase();
  const normalizedType = String(messageType || '').toLowerCase();

  if (normalizedType === 'image' || normalizedMime.startsWith('image/') || (!normalizedMime && imageUrl)) return 'image';
  if (normalizedType === 'audio' || normalizedMime.startsWith('audio/')) return 'audio';
  if (normalizedType === 'pdf' || normalizedMime === 'application/pdf' || normalizedName.endsWith('.pdf')) return 'pdf';
  if (
    normalizedType === 'file' ||
    CHAT_DOCUMENT_MIME_TYPES.has(normalizedMime) ||
    hasDocumentExtension(normalizedName) ||
    (!normalizedMime && attachmentUrl && normalizedType && normalizedType !== 'text')
  ) {
    return 'file';
  }
  return '';
};

export const getChatAttachmentLabel = (type, name = '') => {
  if (type === 'image') return name ? `[Image] ${name}` : '[Image]';
  if (type === 'audio') return name ? `[Audio] ${name}` : '[Audio]';
  if (type === 'pdf') return name ? `[PDF] ${name}` : '[PDF]';
  if (type === 'file') return name ? `[File] ${name}` : '[File]';
  return '';
};

export const validateChatAttachmentFile = (file) => {
  if (!file) return 'No file selected.';
  const attachmentType = getChatAttachmentType({ mime: file.type, name: file.name });
  if (!attachmentType) {
    return 'Please select an image, audio, PDF, or document file.';
  }
  const maxBytes = attachmentType === 'image' ? CHAT_IMAGE_MAX_BYTES : CHAT_FILE_MAX_BYTES;
  if (file.size > maxBytes) {
    return attachmentType === 'image'
      ? 'Image must be 2MB or smaller.'
      : 'Audio and documents must be 8MB or smaller.';
  }
  return '';
};

export const readFileAsDataUrl = (file) =>
  new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result || ''));
    reader.onerror = () => reject(new Error('file_read_failed'));
    reader.readAsDataURL(file);
  });

export const getChatAttachmentPayload = ({ dataUrl = '', name = '', mime = '' } = {}) => {
  const attachmentUrl = String(dataUrl || '');
  const attachmentName = String(name || '').trim();
  const attachmentMime = String(mime || '').trim();
  const messageType = getChatAttachmentType({ mime: attachmentMime, name: attachmentName, attachmentUrl }) || 'text';

  return {
    messageType,
    attachmentUrl,
    attachmentName,
    attachmentMime,
    imageUrl: messageType === 'image' ? attachmentUrl : '',
    imageName: messageType === 'image' ? attachmentName : '',
  };
};

export const getChatMessageAttachment = (msg = {}) => {
  const attachmentUrl = msg.attachmentUrl || msg.imageUrl || '';
  const attachmentName = msg.attachmentName || msg.imageName || '';
  const attachmentMime = msg.attachmentMime || '';
  const attachmentType = getChatAttachmentType({
    mime: attachmentMime,
    name: attachmentName,
    messageType: msg.messageType,
    attachmentUrl,
    imageUrl: msg.imageUrl,
  });

  return {
    attachmentType,
    attachmentUrl,
    attachmentName,
    attachmentMime,
  };
};
