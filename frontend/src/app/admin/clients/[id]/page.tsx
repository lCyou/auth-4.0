'use client';
import React, { useEffect, useState } from 'react';
import {
  Box,
  Button,
  Typography,
  Paper,
  Alert,
  Chip,
  Grid,
  Divider,
} from '@mui/material';
import { useRouter, useParams } from 'next/navigation';
import AdminLayoutWrapper from '@/components/AdminLayoutWrapper';
import { getClient, type Client } from '@/lib/api';

export default function ClientDetailPage() {
  const router = useRouter();
  const params = useParams();
  const clientId = params.id as string;

  const [client, setClient] = useState<Client | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const loadClient = async () => {
      setLoading(true);
      setError('');
      const result = await getClient(clientId);
      if (result.error) {
        setError(result.error);
      } else if (result.data) {
        setClient(result.data);
      }
      setLoading(false);
    };

    if (clientId) {
      loadClient();
    }
  }, [clientId]);

  if (loading) {
    return (
      <AdminLayoutWrapper>
        <Typography>読み込み中...</Typography>
      </AdminLayoutWrapper>
    );
  }

  if (error) {
    return (
      <AdminLayoutWrapper>
        <Alert severity="error">{error}</Alert>
        <Button onClick={() => router.back()} sx={{ mt: 2 }}>
          戻る
        </Button>
      </AdminLayoutWrapper>
    );
  }

  if (!client) {
    return (
      <AdminLayoutWrapper>
        <Alert severity="warning">クライアントが見つかりませんでした</Alert>
        <Button onClick={() => router.back()} sx={{ mt: 2 }}>
          戻る
        </Button>
      </AdminLayoutWrapper>
    );
  }

  return (
    <AdminLayoutWrapper>
      <Box>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
          <Typography variant="h4">クライアント詳細</Typography>
          <Button variant="outlined" onClick={() => router.back()}>
            戻る
          </Button>
        </Box>

        <Paper sx={{ p: 3 }}>
          <Grid container spacing={3}>
            <Grid item xs={12}>
              <Typography variant="subtitle2" color="text.secondary">
                クライアント名
              </Typography>
              <Typography variant="h6">{client.client_name}</Typography>
            </Grid>

            <Grid item xs={12}>
              <Divider />
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                クライアントID
              </Typography>
              <Typography variant="body1" sx={{ fontFamily: 'monospace' }}>
                {client.client_id}
              </Typography>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                クライアントシークレット
              </Typography>
              <Typography variant="body1" sx={{ fontFamily: 'monospace' }}>
                {client.client_secret ? '••••••••••••' : '(設定なし)'}
              </Typography>
            </Grid>

            <Grid item xs={12}>
              <Divider />
            </Grid>

            <Grid item xs={12}>
              <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                リダイレクトURI
              </Typography>
              {client.redirect_uris.map((uri, index) => (
                <Typography
                  key={index}
                  variant="body2"
                  sx={{ fontFamily: 'monospace', mb: 0.5 }}
                >
                  • {uri}
                </Typography>
              ))}
            </Grid>

            <Grid item xs={12}>
              <Divider />
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                Grant Types
              </Typography>
              <Box>
                {client.grant_types.map((type) => (
                  <Chip key={type} label={type} size="small" sx={{ mr: 0.5, mb: 0.5 }} />
                ))}
              </Box>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                Response Types
              </Typography>
              <Box>
                {client.response_types.map((type) => (
                  <Chip key={type} label={type} size="small" sx={{ mr: 0.5, mb: 0.5 }} />
                ))}
              </Box>
            </Grid>

            <Grid item xs={12}>
              <Divider />
            </Grid>

            <Grid item xs={12}>
              <Typography variant="subtitle2" color="text.secondary">
                Scope
              </Typography>
              <Typography variant="body1">{client.scope}</Typography>
            </Grid>

            <Grid item xs={12}>
              <Divider />
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                作成日時
              </Typography>
              <Typography variant="body2">
                {new Date(client.created_at).toLocaleString('ja-JP')}
              </Typography>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                更新日時
              </Typography>
              <Typography variant="body2">
                {new Date(client.updated_at).toLocaleString('ja-JP')}
              </Typography>
            </Grid>
          </Grid>
        </Paper>
      </Box>
    </AdminLayoutWrapper>
  );
}
