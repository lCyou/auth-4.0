'use client';
import { Typography, Paper, Box, Grid, Card, CardContent } from '@mui/material';
import { Apps as AppsIcon, People as PeopleIcon } from '@mui/icons-material';
import AdminLayoutWrapper from '@/components/AdminLayoutWrapper';

export default function AdminDashboard() {
  return (
    <AdminLayoutWrapper>
      <Box>
        <Typography variant="h4" gutterBottom>
          ダッシュボード
        </Typography>
        <Grid container spacing={3} sx={{ mt: 2 }}>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                  <AppsIcon sx={{ fontSize: 40, mr: 2, color: 'primary.main' }} />
                  <Typography variant="h5">クライアント管理</Typography>
                </Box>
                <Typography variant="body2" color="text.secondary">
                  OAuth 2.0 / OpenID Connectクライアントの作成、編集、削除を行います。
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                  <PeopleIcon sx={{ fontSize: 40, mr: 2, color: 'primary.main' }} />
                  <Typography variant="h5">ユーザー管理</Typography>
                </Box>
                <Typography variant="body2" color="text.secondary">
                  登録されたユーザーの閲覧と管理を行います。
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </Box>
    </AdminLayoutWrapper>
  );
}
