import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  Mic,
  MicOff,
  Video,
  VideoOff,
  Phone,
  PhoneOff,
  MonitorUp,
  Maximize2,
  Minimize2,
} from 'lucide-react';
import '../styles/VideoCall.css';

const RTC_CONFIG = {
  iceServers: [
    { urls: 'stun:stun.l.google.com:19302' },
  ],
};

function normalizeRoomId(roomRaw) {
  return String(roomRaw || '')
    .split('_')
    .map((value) => String(value || '').trim().toLowerCase())
    .filter(Boolean)
    .sort()
    .join('_');
}

function formatDuration(totalSeconds) {
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;

  if (hours > 0) {
    return [hours, minutes, seconds]
      .map((value) => String(value).padStart(2, '0'))
      .join(':');
  }

  return [minutes, seconds]
    .map((value) => String(value).padStart(2, '0'))
    .join(':');
}

function getMediaErrorMessage(error) {
  if (!error) return 'Could not access camera or microphone';

  switch (error.name) {
    case 'NotAllowedError':
    case 'PermissionDeniedError':
      return 'Camera or microphone permission was denied';
    case 'NotFoundError':
    case 'DevicesNotFoundError':
      return 'Camera or microphone was not found';
    case 'NotReadableError':
    case 'TrackStartError':
      return 'Camera is busy in another app. Close it and try again';
    case 'OverconstrainedError':
    case 'ConstraintNotSatisfiedError':
      return 'This camera setup is not supported on this device';
    default:
      return 'Could not access camera or microphone';
  }
}

export default function VideoCall({
  socket,
  roomId,
  currentUserEmail,
  currentUserName,
  peerLabel = 'Other participant',
  enabled = true,
  compact = false,
  externalIncomingCall = null,
  onIncomingCallCleared = null,
}) {
  const panelRef = useRef(null);
  const localVideoRef = useRef(null);
  const remoteVideoRef = useRef(null);
  const peerConnectionRef = useRef(null);
  const localStreamRef = useRef(null);
  const remoteStreamRef = useRef(null);
  const pendingCandidatesRef = useRef([]);
  const joinedRoomRef = useRef('');
  const activeScreenTrackRef = useRef(null);
  const callStartedAtRef = useRef(null);
  const joinRoomFnRef = useRef(() => {});
  const resetCallStateRef = useRef(async () => {});

  const [callStatus, setCallStatus] = useState('idle');
  const [incomingOffer, setIncomingOffer] = useState(null);
  const [incomingFrom, setIncomingFrom] = useState('');
  const [isMuted, setIsMuted] = useState(false);
  const [isCameraOff, setIsCameraOff] = useState(false);
  const [isAudioOnly, setIsAudioOnly] = useState(false);
  const [isSharingScreen, setIsSharingScreen] = useState(false);
  const [callSeconds, setCallSeconds] = useState(0);
  const [callError, setCallError] = useState('');
  const [hasLocalPreview, setHasLocalPreview] = useState(false);
  const [hasRemotePreview, setHasRemotePreview] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const signalingRoomId = useMemo(() => normalizeRoomId(roomId), [roomId]);
  const normalizedCurrentUserEmail = useMemo(
    () => String(currentUserEmail || '').trim().toLowerCase(),
    [currentUserEmail]
  );

  const canCall = Boolean(socket && signalingRoomId && enabled);
  const isCallActive = callStatus === 'calling' || callStatus === 'ringing' || callStatus === 'connected';
  const externalOfferForRoom = externalIncomingCall?.room === signalingRoomId ? externalIncomingCall.offer : null;
  const effectiveIncomingOffer = incomingOffer || externalOfferForRoom;
  const effectiveIncomingFrom = incomingFrom || (externalIncomingCall?.room === signalingRoomId ? externalIncomingCall.from : '');
  const hasIncomingRequest = Boolean(effectiveIncomingOffer);
  const showVideoStage = !compact || isCallActive || hasIncomingRequest;

  const statusLabel = useMemo(() => {
    if (callError) return callError;
    if (hasIncomingRequest) return `${effectiveIncomingFrom || peerLabel} is calling`;
    if (callStatus === 'calling') return 'Calling...';
    if (callStatus === 'ringing') return 'Connecting...';
    if (callStatus === 'connected') return `Live • ${formatDuration(callSeconds)}`;
    return canCall ? 'Ready for a private call' : 'Call unavailable';
  }, [callError, hasIncomingRequest, effectiveIncomingFrom, peerLabel, callStatus, callSeconds, canCall]);

  const syncVideoElement = async (element, stream, { muted = false } = {}) => {
    if (!element) return;
    element.srcObject = stream || null;
    element.muted = muted;

    if (!stream) return;

    try {
      await element.play();
    } catch (err) {
      // Autoplay can race with layout updates; a user gesture from call controls will recover.
      console.warn('Video autoplay was blocked or deferred', err);
    }
  };

  const clearPeerConnection = () => {
    if (peerConnectionRef.current) {
      peerConnectionRef.current.onicecandidate = null;
      peerConnectionRef.current.ontrack = null;
      peerConnectionRef.current.onconnectionstatechange = null;
      peerConnectionRef.current.close();
      peerConnectionRef.current = null;
    }

    pendingCandidatesRef.current = [];
    remoteStreamRef.current = null;
    syncVideoElement(remoteVideoRef.current, null);
    setHasRemotePreview(false);
  };

  const stopScreenSharing = async () => {
    const screenTrack = activeScreenTrackRef.current;
    if (!screenTrack) return;

    screenTrack.onended = null;
    screenTrack.stop();
    activeScreenTrackRef.current = null;
    setIsSharingScreen(false);

    const stream = localStreamRef.current;
    const cameraTrack = stream?.getVideoTracks?.()[0];
    const sender = peerConnectionRef.current
      ?.getSenders()
      ?.find((item) => item.track?.kind === 'video');

    if (sender && cameraTrack) {
      await sender.replaceTrack(cameraTrack);
    }
  };

  const stopLocalMedia = async () => {
    await stopScreenSharing();

    if (localStreamRef.current) {
      localStreamRef.current.getTracks().forEach((track) => track.stop());
      localStreamRef.current = null;
    }

    syncVideoElement(localVideoRef.current, null, { muted: true });
    setHasLocalPreview(false);
    setIsAudioOnly(false);
  };

  const resetCallState = async ({ keepJoinedRoom = true } = {}) => {
    clearPeerConnection();
    await stopLocalMedia();
    setIncomingOffer(null);
    setIncomingFrom('');
    setCallStatus(keepJoinedRoom ? 'idle' : 'idle');
    setCallError('');
    setCallSeconds(0);
    callStartedAtRef.current = null;
    if (!keepJoinedRoom) {
      joinedRoomRef.current = '';
    }
  };

  const ensureLocalMedia = async () => {
    if (localStreamRef.current) return localStreamRef.current;

    let stream;

    try {
      stream = await navigator.mediaDevices.getUserMedia({
        video: true,
        audio: true,
      });
      setIsAudioOnly(false);
      setIsCameraOff(false);
    } catch (error) {
      const canFallbackToAudio =
        error?.name === 'NotReadableError' ||
        error?.name === 'TrackStartError' ||
        error?.name === 'OverconstrainedError' ||
        error?.name === 'ConstraintNotSatisfiedError';

      if (!canFallbackToAudio) {
        throw error;
      }

      stream = await navigator.mediaDevices.getUserMedia({
        video: false,
        audio: true,
      });
      setIsAudioOnly(true);
      setIsCameraOff(true);
      setCallError('Camera unavailable, continuing with audio only');
    }

    localStreamRef.current = stream;
    setIsMuted(false);

    syncVideoElement(localVideoRef.current, stream, { muted: true });
    setHasLocalPreview(stream.getVideoTracks().length > 0);

    return stream;
  };

  const flushPendingCandidates = async () => {
    if (!peerConnectionRef.current || !pendingCandidatesRef.current.length) return;

    const queued = [...pendingCandidatesRef.current];
    pendingCandidatesRef.current = [];

    for (const candidate of queued) {
      try {
        await peerConnectionRef.current.addIceCandidate(candidate);
      } catch (err) {
        console.error('Failed to apply queued ICE candidate', err);
      }
    }
  };

  const createPeerConnection = async () => {
    if (peerConnectionRef.current) return peerConnectionRef.current;

    const stream = await ensureLocalMedia();
    const connection = new RTCPeerConnection(RTC_CONFIG);

    remoteStreamRef.current = new MediaStream();
    syncVideoElement(remoteVideoRef.current, remoteStreamRef.current);

    stream.getTracks().forEach((track) => {
      connection.addTrack(track, stream);
    });

    connection.onicecandidate = (event) => {
      if (!event.candidate || !socket || !signalingRoomId) return;
      socket.emit('ice-candidate', {
        room: signalingRoomId,
        candidate: event.candidate,
      });
    };

    connection.ontrack = (event) => {
      const [streamFromPeer] = event.streams;
      const targetStream = remoteStreamRef.current || new MediaStream();

      if (streamFromPeer) {
        streamFromPeer.getTracks().forEach((track) => {
          if (!targetStream.getTracks().some((item) => item.id === track.id)) {
            targetStream.addTrack(track);
          }
        });
      } else if (!targetStream.getTracks().some((item) => item.id === event.track.id)) {
        targetStream.addTrack(event.track);
      }

      remoteStreamRef.current = targetStream;
      syncVideoElement(remoteVideoRef.current, targetStream);
      setHasRemotePreview(targetStream.getVideoTracks().length > 0);
    };

    connection.onconnectionstatechange = () => {
      const state = connection.connectionState;
      if (state === 'connected') {
        setCallStatus('connected');
        setCallError('');
        if (!callStartedAtRef.current) {
          callStartedAtRef.current = Date.now();
        }
      } else if (state === 'failed') {
        setCallError('Connection failed');
      } else if (state === 'disconnected') {
        setCallError('Peer disconnected');
      }
    };

    peerConnectionRef.current = connection;
    await flushPendingCandidates();
    return connection;
  };

  const joinRoom = () => {
    if (!socket || !signalingRoomId || joinedRoomRef.current === signalingRoomId || !enabled) {
      return;
    }
    socket.emit('join-room', { room: signalingRoomId });
  };

  useEffect(() => {
    joinRoomFnRef.current = joinRoom;
    resetCallStateRef.current = resetCallState;
  });

  const startCall = async () => {
    if (!canCall) return;

    try {
      setCallError('');
      setIncomingOffer(null);
      setIncomingFrom('');
      setCallStatus('calling');
      joinRoom();

      const connection = await createPeerConnection();
      const offer = await connection.createOffer();
      await connection.setLocalDescription(offer);

      socket.emit('offer', {
        room: signalingRoomId,
        offer,
      });
    } catch (err) {
      console.error('Failed to start call', err);
      setCallStatus('idle');
      setCallError(getMediaErrorMessage(err));
    }
  };

  const acceptCall = async () => {
    if (!effectiveIncomingOffer || !socket || !signalingRoomId) return;

    try {
      setCallError('');
      setCallStatus('ringing');
      joinRoom();

      const connection = await createPeerConnection();
      await connection.setRemoteDescription(new RTCSessionDescription(effectiveIncomingOffer));
      await flushPendingCandidates();

      const answer = await connection.createAnswer();
      await connection.setLocalDescription(answer);

      socket.emit('answer', {
        room: signalingRoomId,
        answer,
      });

      setIncomingOffer(null);
      setIncomingFrom('');
      onIncomingCallCleared?.();
    } catch (err) {
      console.error('Failed to accept call', err);
      setCallStatus('idle');
      setCallError(getMediaErrorMessage(err));
    }
  };

  const declineIncomingCall = () => {
    setIncomingOffer(null);
    setIncomingFrom('');
    setCallStatus('idle');
    onIncomingCallCleared?.();
  };

  const endCall = async (notifyPeer = true) => {
    if (notifyPeer && socket && signalingRoomId) {
      socket.emit('call-ended', { room: signalingRoomId });
    }
    onIncomingCallCleared?.();
    await resetCallState();
  };

  const toggleMute = () => {
    const audioTrack = localStreamRef.current?.getAudioTracks?.()[0];
    if (!audioTrack) return;
    audioTrack.enabled = !audioTrack.enabled;
    setIsMuted(!audioTrack.enabled);
  };

  const toggleCamera = () => {
    const videoTrack = localStreamRef.current?.getVideoTracks?.()[0];
    if (!videoTrack) return;
    videoTrack.enabled = !videoTrack.enabled;
    setIsCameraOff(!videoTrack.enabled);
  };

  const toggleScreenShare = async () => {
    if (!peerConnectionRef.current || !localStreamRef.current) return;

    if (isSharingScreen) {
      await stopScreenSharing();
      return;
    }

    try {
      const displayStream = await navigator.mediaDevices.getDisplayMedia({
        video: true,
      });
      const screenTrack = displayStream.getVideoTracks()[0];
      const sender = peerConnectionRef.current
        .getSenders()
        .find((item) => item.track?.kind === 'video');

      if (!sender || !screenTrack) return;

      activeScreenTrackRef.current = screenTrack;
      await sender.replaceTrack(screenTrack);
      setIsSharingScreen(true);

      if (localVideoRef.current) {
        syncVideoElement(localVideoRef.current, displayStream, { muted: true });
      }

      screenTrack.onended = async () => {
        if (localVideoRef.current && localStreamRef.current) {
          syncVideoElement(localVideoRef.current, localStreamRef.current, { muted: true });
        }
        await stopScreenSharing();
      };
    } catch (err) {
      console.error('Screen sharing failed', err);
      setCallError('Could not share screen');
    }
  };

  useEffect(() => {
    if (!canCall) {
      resetCallStateRef.current({ keepJoinedRoom: false });
      return undefined;
    }

    joinRoomFnRef.current();

    const handleConnect = () => {
      joinRoomFnRef.current();
    };

    const handleAuthSuccess = () => {
      joinRoomFnRef.current();
    };

    socket?.on?.('connect', handleConnect);
    socket?.on?.('auth_success', handleAuthSuccess);

    return () => {
      socket?.off?.('connect', handleConnect);
      socket?.off?.('auth_success', handleAuthSuccess);
      resetCallStateRef.current({ keepJoinedRoom: false });
    };
  }, [canCall, signalingRoomId, socket]);

  useEffect(() => {
    if (!socket || !signalingRoomId) return undefined;

    const handleRoomJoined = ({ room }) => {
      if (room !== signalingRoomId) return;
      joinedRoomRef.current = room;
    };

    const handleOffer = async ({ room, offer, from }) => {
      if (room !== signalingRoomId || from === normalizedCurrentUserEmail) return;
      setIncomingOffer(offer);
      setIncomingFrom(from || peerLabel);
      setCallStatus('ringing');
      setCallError('');
    };

    const handleAnswer = async ({ room, answer }) => {
      if (room !== signalingRoomId || !peerConnectionRef.current) return;
      await peerConnectionRef.current.setRemoteDescription(
        new RTCSessionDescription(answer)
      );
      await flushPendingCandidates();
    };

    const handleIceCandidate = async ({ room, candidate }) => {
      if (room !== signalingRoomId || !candidate) return;
      const rtcCandidate = new RTCIceCandidate(candidate);

      if (!peerConnectionRef.current || !peerConnectionRef.current.remoteDescription) {
        pendingCandidatesRef.current.push(rtcCandidate);
        return;
      }

      try {
        await peerConnectionRef.current.addIceCandidate(rtcCandidate);
      } catch (err) {
        console.error('Failed to add ICE candidate', err);
      }
    };

    const handleCallEnded = async ({ room }) => {
      if (room !== signalingRoomId) return;
      setCallError('Call ended');
      await resetCallStateRef.current();
    };

    const handlePeerDisconnected = async ({ room }) => {
      if (room !== signalingRoomId) return;
      setCallError('Peer disconnected');
      await resetCallStateRef.current();
    };

    const handleCallDenied = ({ room, message }) => {
      if (room && room !== signalingRoomId) return;
      setCallStatus('idle');
      setCallError(message || 'Call access denied');
    };

    socket.on('room_joined', handleRoomJoined);
    socket.on('offer', handleOffer);
    socket.on('answer', handleAnswer);
    socket.on('ice-candidate', handleIceCandidate);
    socket.on('call-ended', handleCallEnded);
    socket.on('peer-disconnected', handlePeerDisconnected);
    socket.on('call_access_denied', handleCallDenied);

    return () => {
      socket.off('room_joined', handleRoomJoined);
      socket.off('offer', handleOffer);
      socket.off('answer', handleAnswer);
      socket.off('ice-candidate', handleIceCandidate);
      socket.off('call-ended', handleCallEnded);
      socket.off('peer-disconnected', handlePeerDisconnected);
      socket.off('call_access_denied', handleCallDenied);
    };
  }, [socket, signalingRoomId, normalizedCurrentUserEmail, peerLabel]);

  useEffect(() => {
    if (callStatus !== 'connected') return undefined;

    const interval = window.setInterval(() => {
      if (!callStartedAtRef.current) return;
      setCallSeconds(Math.floor((Date.now() - callStartedAtRef.current) / 1000));
    }, 1000);

    return () => window.clearInterval(interval);
  }, [callStatus]);

  useEffect(() => {
    const handleFullscreenChange = () => {
      setIsFullscreen(document.fullscreenElement === panelRef.current);
    };

    document.addEventListener('fullscreenchange', handleFullscreenChange);
    return () => document.removeEventListener('fullscreenchange', handleFullscreenChange);
  }, []);

  const toggleFullscreen = async () => {
    const panel = panelRef.current;
    if (!panel) return;

    try {
      if (document.fullscreenElement === panel) {
        await document.exitFullscreen();
      } else {
        await panel.requestFullscreen();
      }
    } catch (err) {
      console.error('Failed to toggle fullscreen', err);
      setCallError('Fullscreen is not available here');
    }
  };

  return (
    <section
      ref={panelRef}
      className={`vc-panel ${compact ? 'vc-panel-compact' : ''} ${isCallActive ? 'vc-panel-live' : ''} ${isFullscreen ? 'vc-panel-fullscreen' : ''}`}
    >
      <div className="vc-header">
        <div>
          <div className="vc-kicker">{compact ? 'Call controls' : 'Private call'}</div>
          <h3>{compact ? peerLabel : `Video and audio with ${peerLabel}`}</h3>
        </div>
        <div className={`vc-status ${isCallActive ? 'live' : ''}`}>
          {statusLabel}
        </div>
      </div>

      {hasIncomingRequest ? (
        <div className="vc-incoming">
          <span>{incomingFrom || peerLabel} wants to start a call.</span>
          <div className="vc-inline-actions">
            <button type="button" className="vc-btn vc-btn-primary" onClick={acceptCall}>
              <Phone size={16} />
              Accept
            </button>
            <button type="button" className="vc-btn vc-btn-ghost" onClick={declineIncomingCall}>
              <PhoneOff size={16} />
              Decline
            </button>
          </div>
        </div>
      ) : null}

      <div className="vc-actions">
        <button
          type="button"
          className="vc-btn vc-btn-primary"
          onClick={startCall}
          disabled={!canCall || isCallActive}
        >
          <Phone size={16} />
          Start call
        </button>

        <button
          type="button"
          className={`vc-icon-btn ${isMuted ? 'active' : ''}`}
          onClick={toggleMute}
          disabled={!isCallActive}
          aria-label={isMuted ? 'Unmute microphone' : 'Mute microphone'}
        >
          {isMuted ? <MicOff size={16} /> : <Mic size={16} />}
        </button>

        <button
          type="button"
          className={`vc-icon-btn ${isCameraOff ? 'active' : ''}`}
          onClick={toggleCamera}
          disabled={!isCallActive || isAudioOnly}
          aria-label={isCameraOff ? 'Turn camera on' : 'Turn camera off'}
        >
          {isCameraOff ? <VideoOff size={16} /> : <Video size={16} />}
        </button>

        <button
          type="button"
          className={`vc-icon-btn ${isSharingScreen ? 'active' : ''}`}
          onClick={toggleScreenShare}
          disabled={!isCallActive || isAudioOnly}
          aria-label={isSharingScreen ? 'Stop screen sharing' : 'Share screen'}
        >
          <MonitorUp size={16} />
        </button>

        <button
          type="button"
          className="vc-icon-btn"
          onClick={toggleFullscreen}
          aria-label={isFullscreen ? 'Exit fullscreen' : 'Open fullscreen'}
        >
          {isFullscreen ? <Minimize2 size={16} /> : <Maximize2 size={16} />}
        </button>

        <button
          type="button"
          className="vc-btn vc-btn-danger"
          onClick={() => endCall(true)}
          disabled={!isCallActive && !hasIncomingRequest}
        >
          <PhoneOff size={16} />
          End
        </button>
      </div>

      {showVideoStage ? (
        <div className={`vc-grid ${isCallActive ? 'vc-grid-live' : ''}`}>
          <div className="vc-video-card vc-video-card-remote">
            <div className="vc-video-label">{peerLabel}</div>
            <video ref={remoteVideoRef} autoPlay playsInline className="vc-video" />
            {!hasRemotePreview ? (
              <div className="vc-video-empty">Waiting for remote stream</div>
            ) : null}
          </div>

          <div className="vc-video-card vc-video-card-local">
            <div className="vc-video-label">You</div>
            <video ref={localVideoRef} autoPlay muted playsInline className="vc-video" />
            {!hasLocalPreview ? (
              <div className="vc-video-empty">{isAudioOnly ? 'Audio only' : 'Camera preview'}</div>
            ) : null}
          </div>
        </div>
      ) : null}

      <div className="vc-footer">
        <span>STUN: Google public server</span>
        <span>{enabled ? 'Payment verified for room' : 'Call locked until access is verified'}</span>
        <span>{currentUserName || currentUserEmail}</span>
      </div>
    </section>
  );
}
