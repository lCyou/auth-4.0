'use client';
import React, { useEffect, useState } from 'react';
import {
  Box,
  Button,
  Typography,
  Paper,
  Alert,
  Grid,
  Divider,
  Avatar,
  Chip,
} from '@mui/material';
import { useRouter, useParams } from 'next/navigation';
import AdminLayoutWrapper from '@/components/AdminLayoutWrapper';
import { getUser, type User } from '@/lib/api';

export default function UserDetailPage() {
  const router = useRouter();
  const params = useParams();
  const userId = params.id as string;

  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const loadUser = async () => {
      setLoading(true);
      setError('');
      const result = await getUser(userId);
      if (result.error) {
        setError(result.error);
      } else if (result.data) {
        setUser(result.data);
      }
      setLoading(false);
    };

    if (userId) {
      loadUser();
    }
  }, [userId]);

  const getProviderColor = (provider: string) => {
    switch (provider) {
      case 'google':
        return 'error';
      case 'github':
        return 'default';
      default:
        return 'primary';
    }
  };

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

  if (!user) {
    return (
      <AdminLayoutWrapper>
        <Alert severity="warning">ユーザーが見つかりませんでした</Alert>
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
          <Typography variant="h4">ユーザー詳細</Typography>
          <Button variant="outlined" onClick={() => router.back()}>
            戻る
          </Button>
        </Box>

        <Paper sx={{ p: 3 }}>
          <Grid container spacing={3}>
            <Grid item xs={12}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <Avatar
                  src={user.picture}
                  alt={user.name}
                  sx={{ width: 64, height: 64 }}
                >
                  {user.name.charAt(0)}
                </Avatar>
                <Box>
                  <Typography variant="h5">{user.name}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    {user.email}
                  </Typography>
                </Box>
              </Box>
            </Grid>

            <Grid item xs={12}>
              <Divider />
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                ユーザーID
              </Typography>
              <Typography variant="body1" sx={{ fontFamily: 'monospace' }}>
                {user.id}
              </Typography>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                プロバイダー
              </Typography>
              <Box sx={{ mt: 1 }}>
                <Chip
                  label={user.provider}
                  color={getProviderColor(user.provider)}
                />
              </Box>
            </Grid>

            <Grid item xs={12}>
              <Divider />
            </Grid>

            <Grid item xs={12}>
              <Typography variant="subtitle2" color="text.secondary">
                プロバイダーユーザーID
              </Typography>
              <Typography variant="body1" sx={{ fontFamily: 'monospace' }}>
                {user.provider_user_id}
              </Typography>
            </Grid>

            <Grid item xs={12}>
              <Divider />
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                登録日時
              </Typography>
              <Typography variant="body2">
                {new Date(user.created_at).toLocaleString('ja-JP')}
              </Typography>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                更新日時
              </Typography>
              <Typography variant="body2">
                {new Date(user.updated_at).toLocaleString('ja-JP')}
              </Typography>
            </Grid>
          </Grid>
        </Paper>
      </Box>
    </AdminLayoutWrapper>
  );
}
