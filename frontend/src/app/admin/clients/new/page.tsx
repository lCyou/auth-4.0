'use client';
import React, { useState } from 'react';
import {
  Box,
  Button,
  Typography,
  Paper,
  TextField,
  Alert,
  FormGroup,
  FormControlLabel,
  Checkbox,
  Chip,
} from '@mui/material';
import { useRouter } from 'next/navigation';
import AdminLayoutWrapper from '@/components/AdminLayoutWrapper';
import { createClient } from '@/lib/api';

const AVAILABLE_GRANT_TYPES = [
  'authorization_code',
  'refresh_token',
  'client_credentials',
];

const AVAILABLE_RESPONSE_TYPES = ['code', 'token', 'id_token'];

export default function NewClientPage() {
  const router = useRouter();
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  
  const [clientName, setClientName] = useState('');
  const [clientId, setClientId] = useState('');
  const [clientSecret, setClientSecret] = useState('');
  const [redirectUris, setRedirectUris] = useState<string[]>(['']);
  const [scope, setScope] = useState('openid profile email');
  const [grantTypes, setGrantTypes] = useState<string[]>(['authorization_code', 'refresh_token']);
  const [responseTypes, setResponseTypes] = useState<string[]>(['code']);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    const filteredRedirectUris = redirectUris.filter((uri) => uri.trim() !== '');

    if (filteredRedirectUris.length === 0) {
      setError('リダイレクトURIを1つ以上入力してください');
      setLoading(false);
      return;
    }

    const result = await createClient({
      client_id: clientId,
      client_secret: clientSecret,
      client_name: clientName,
      redirect_uris: filteredRedirectUris,
      grant_types: grantTypes,
      response_types: responseTypes,
      scope: scope,
    });

    if (result.error) {
      setError(result.error);
      setLoading(false);
    } else {
      router.push('/admin/clients');
    }
  };

  const handleRedirectUriChange = (index: number, value: string) => {
    const newUris = [...redirectUris];
    newUris[index] = value;
    setRedirectUris(newUris);
  };

  const addRedirectUri = () => {
    setRedirectUris([...redirectUris, '']);
  };

  const removeRedirectUri = (index: number) => {
    const newUris = redirectUris.filter((_, i) => i !== index);
    setRedirectUris(newUris);
  };

  const handleGrantTypeChange = (type: string) => {
    if (grantTypes.includes(type)) {
      setGrantTypes(grantTypes.filter((t) => t !== type));
    } else {
      setGrantTypes([...grantTypes, type]);
    }
  };

  const handleResponseTypeChange = (type: string) => {
    if (responseTypes.includes(type)) {
      setResponseTypes(responseTypes.filter((t) => t !== type));
    } else {
      setResponseTypes([...responseTypes, type]);
    }
  };

  return (
    <AdminLayoutWrapper>
      <Box>
        <Typography variant="h4" gutterBottom>
          新規クライアント作成
        </Typography>

        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        <Paper sx={{ p: 3, mt: 3 }}>
          <Box component="form" onSubmit={handleSubmit}>
            <TextField
              fullWidth
              label="クライアント名"
              value={clientName}
              onChange={(e) => setClientName(e.target.value)}
              required
              margin="normal"
            />

            <TextField
              fullWidth
              label="クライアントID"
              value={clientId}
              onChange={(e) => setClientId(e.target.value)}
              required
              margin="normal"
              helperText="一意の識別子を入力してください"
            />

            <TextField
              fullWidth
              label="クライアントシークレット"
              value={clientSecret}
              onChange={(e) => setClientSecret(e.target.value)}
              required
              margin="normal"
              type="password"
              helperText="安全なランダム文字列を生成してください"
            />

            <Box sx={{ mt: 3, mb: 2 }}>
              <Typography variant="subtitle1" gutterBottom>
                リダイレクトURI
              </Typography>
              {redirectUris.map((uri, index) => (
                <Box key={index} sx={{ display: 'flex', gap: 1, mb: 1 }}>
                  <TextField
                    fullWidth
                    value={uri}
                    onChange={(e) => handleRedirectUriChange(index, e.target.value)}
                    placeholder="https://example.com/callback"
                  />
                  {redirectUris.length > 1 && (
                    <Button
                      variant="outlined"
                      color="error"
                      onClick={() => removeRedirectUri(index)}
                    >
                      削除
                    </Button>
                  )}
                </Box>
              ))}
              <Button variant="outlined" onClick={addRedirectUri} size="small">
                URIを追加
              </Button>
            </Box>

            <Box sx={{ mt: 3 }}>
              <Typography variant="subtitle1" gutterBottom>
                Grant Types
              </Typography>
              <FormGroup>
                {AVAILABLE_GRANT_TYPES.map((type) => (
                  <FormControlLabel
                    key={type}
                    control={
                      <Checkbox
                        checked={grantTypes.includes(type)}
                        onChange={() => handleGrantTypeChange(type)}
                      />
                    }
                    label={type}
                  />
                ))}
              </FormGroup>
            </Box>

            <Box sx={{ mt: 3 }}>
              <Typography variant="subtitle1" gutterBottom>
                Response Types
              </Typography>
              <FormGroup>
                {AVAILABLE_RESPONSE_TYPES.map((type) => (
                  <FormControlLabel
                    key={type}
                    control={
                      <Checkbox
                        checked={responseTypes.includes(type)}
                        onChange={() => handleResponseTypeChange(type)}
                      />
                    }
                    label={type}
                  />
                ))}
              </FormGroup>
            </Box>

            <TextField
              fullWidth
              label="Scope"
              value={scope}
              onChange={(e) => setScope(e.target.value)}
              required
              margin="normal"
              helperText="スペース区切りで入力してください (例: openid profile email)"
            />

            <Box sx={{ mt: 3, display: 'flex', gap: 2 }}>
              <Button
                type="submit"
                variant="contained"
                disabled={loading || !clientName || !clientId || !clientSecret}
              >
                {loading ? '作成中...' : '作成'}
              </Button>
              <Button variant="outlined" onClick={() => router.back()}>
                キャンセル
              </Button>
            </Box>
          </Box>
        </Paper>
      </Box>
    </AdminLayoutWrapper>
  );
}
