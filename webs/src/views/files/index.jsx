import { useState } from 'react';
import useSWR, { useSWRConfig } from 'swr';
import { useTranslation } from 'react-i18next';
import { Alert, Button, CircularProgress, Divider, Stack, TextField, Typography } from '@mui/material';
import MainCard from 'ui-component/cards/MainCard';
import request from 'api/request';

const filesPath = '/v1/files';
const uploadLimit = 1024 * 1024;
const load = async (url) => (await request.get(url)).data ?? [];

function shareURL(file, token) {
  const url = new URL(`/api/v1/file-download/${encodeURIComponent(file.name)}`, window.location.origin);
  url.searchParams.set('token', token);
  url.searchParams.set('filename', file.displayName || file.name);
  return url.href;
}

function FileShares({ file }) {
  const { t } = useTranslation();
  const path = `${filesPath}/${encodeURIComponent(file.name)}/shares`;
  const { data: shares, error, isLoading, mutate } = useSWR(path, load);
  const [working, setWorking] = useState(false);
  const [failure, setFailure] = useState(false);
  const [copied, setCopied] = useState('');

  async function changeShare(method, url) {
    setFailure(false);
    setWorking(true);
    try {
      await request({ method, url });
      await mutate();
    } catch {
      setFailure(true);
    } finally {
      setWorking(false);
    }
  }

  async function copy(token) {
    setFailure(false);
    try {
      await navigator.clipboard.writeText(shareURL(file, token));
      setCopied(token);
    } catch {
      setFailure(true);
    }
  }

  return (
    <Stack spacing={1.5}>
      <Button
        variant="contained"
        disabled={working || isLoading}
        onClick={() => changeShare('post', path)}
        sx={{ alignSelf: 'flex-start' }}
      >
        {t('fileSharing.createLink')}
      </Button>
      {(error || failure) && <Alert severity="error">{t('fileSharing.actionFailed')}</Alert>}
      {isLoading && <CircularProgress size={20} />}
      {shares?.map((share) => {
        const expired = (share.exp > 0 && share.exp <= Date.now()) || (share.mode === 'count' && share.usedCount >= share.count);
        return (
          <Stack key={share.token} spacing={1}>
            <TextField
              fullWidth
              size="small"
              label={t('fileSharing.link')}
              value={shareURL(file, share.token)}
              slotProps={{ input: { readOnly: true } }}
              helperText={expired ? t('fileSharing.expired') : share.exp ? new Date(share.exp).toLocaleString() : t('fileSharing.noExpiry')}
            />
            <Stack direction="row" spacing={1}>
              <Button disabled={expired} onClick={() => copy(share.token)}>
                {t(copied === share.token ? 'fileSharing.copied' : 'fileSharing.copy')}
              </Button>
              <Button color="error" disabled={working} onClick={() => changeShare('delete', `${path}/${encodeURIComponent(share.token)}`)}>
                {t('fileSharing.revoke')}
              </Button>
            </Stack>
          </Stack>
        );
      })}
    </Stack>
  );
}

export default function Files() {
  const { t } = useTranslation();
  const { data: files, error, isLoading } = useSWR(filesPath, load);
  const { mutate } = useSWRConfig();
  const [selected, setSelected] = useState('');
  const [uploading, setUploading] = useState(false);
  const [failure, setFailure] = useState('');

  async function upload(event) {
    const input = event.currentTarget;
    const file = input.files?.[0];
    input.value = '';
    if (!file) return;
    setFailure('');
    if (file.size >= uploadLimit) {
      setFailure('fileSharing.tooLarge');
      return;
    }
    setUploading(true);
    try {
      const bytes = await file.arrayBuffer();
      let content;
      try {
        content = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
      } catch {
        setFailure('fileSharing.invalidText');
        return;
      }
      if (content.includes('\0')) {
        setFailure('fileSharing.invalidText');
        return;
      }
      const data = JSON.stringify({ name: file.name, content });
      if (new Blob([data]).size > uploadLimit) {
        setFailure('fileSharing.tooLarge');
        return;
      }
      const response = await request.post(filesPath, data);
      setSelected(response.data.name);
      await mutate(filesPath);
    } catch {
      setFailure('fileSharing.actionFailed');
    } finally {
      setUploading(false);
    }
  }

  return (
    <MainCard title={t('navigation.items.files')}>
      <Stack spacing={2}>
        <Stack spacing={1} alignItems="flex-start">
          <Button component="label" variant="contained" disabled={uploading || Boolean(error)}>
            {t(uploading ? 'fileSharing.uploading' : 'fileSharing.upload')}
            <input hidden type="file" onChange={upload} disabled={uploading || Boolean(error)} />
          </Button>
          <Typography variant="body2" color="text.secondary">
            {t('fileSharing.uploadHint')}
          </Typography>
        </Stack>
        {error && (
          <Alert severity="error">{t(error.response?.status === 503 ? 'fileSharing.configure' : 'fileSharing.actionFailed')}</Alert>
        )}
        {failure && <Alert severity="error">{t(failure)}</Alert>}
        {isLoading && <CircularProgress size={24} />}
        {files?.length === 0 && <Typography color="text.secondary">{t('fileSharing.empty')}</Typography>}
        {files?.map((file) => (
          <Stack key={file.name} spacing={1.5}>
            <Divider />
            <Stack direction="row" justifyContent="space-between" alignItems="center" spacing={2}>
              <Typography variant="subtitle1" sx={{ overflowWrap: 'anywhere' }}>
                {file.displayName || file.name}
              </Typography>
              <Button onClick={() => setSelected(selected === file.name ? '' : file.name)}>
                {t(selected === file.name ? 'fileSharing.closeLinks' : 'fileSharing.manageLinks')}
              </Button>
            </Stack>
            {selected === file.name && <FileShares file={file} />}
          </Stack>
        ))}
      </Stack>
    </MainCard>
  );
}
