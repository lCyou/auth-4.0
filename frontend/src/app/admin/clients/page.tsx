'use client';
import React, { useEffect, useState } from 'react';
import {
  Box,
  Button,
  Typography,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Alert,
  Chip,
} from '@mui/material';
import {
  Add as AddIcon,
  Delete as DeleteIcon,
  Visibility as VisibilityIcon,
} from '@mui/icons-material';
import { useRouter } from 'next/navigation';
import AdminLayoutWrapper from '@/components/AdminLayoutWrapper';
import { listClients, deleteClient, type Client } from '@/lib/api';

export default function ClientsPage() {
  const [clients, setClients] = useState<Client[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [selectedClient, setSelectedClient] = useState<Client | null>(null);
  const router = useRouter();

  const loadClients = async () => {
    setLoading(true);
    setError('');
    const result = await listClients();
    if (result.error) {
      setError(result.error);
    } else if (result.data) {
      setClients(result.data);
    }
    setLoading(false);
  };

  useEffect(() => {
    loadClients();
  }, []);

  const handleDelete = async () => {
    if (!selectedClient) return;

    const result = await deleteClient(selectedClient.id);
    if (result.error) {
      setError(result.error);
    } else {
      await loadClients();
    }
    setDeleteDialogOpen(false);
    setSelectedClient(null);
  };

  const openDeleteDialog = (client: Client) => {
    setSelectedClient(client);
    setDeleteDialogOpen(true);
  };

  return (
    <AdminLayoutWrapper>
      <Box>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
          <Typography variant="h4">クライアント管理</Typography>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => router.push('/admin/clients/new')}
          >
            新規作成
          </Button>
        </Box>

        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>クライアント名</TableCell>
                <TableCell>クライアントID</TableCell>
                <TableCell>Grant Types</TableCell>
                <TableCell>作成日</TableCell>
                <TableCell align="right">操作</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={5} align="center">
                    読み込み中...
                  </TableCell>
                </TableRow>
              ) : clients.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} align="center">
                    クライアントが登録されていません
                  </TableCell>
                </TableRow>
              ) : (
                clients.map((client) => (
                  <TableRow key={client.id}>
                    <TableCell>{client.client_name}</TableCell>
                    <TableCell>
                      <code>{client.client_id}</code>
                    </TableCell>
                    <TableCell>
                      {client.grant_types.map((type) => (
                        <Chip key={type} label={type} size="small" sx={{ mr: 0.5 }} />
                      ))}
                    </TableCell>
                    <TableCell>
                      {new Date(client.created_at).toLocaleDateString('ja-JP')}
                    </TableCell>
                    <TableCell align="right">
                      <IconButton
                        size="small"
                        onClick={() => router.push(`/admin/clients/${client.id}`)}
                      >
                        <VisibilityIcon />
                      </IconButton>
                      <IconButton
                        size="small"
                        color="error"
                        onClick={() => openDeleteDialog(client)}
                      >
                        <DeleteIcon />
                      </IconButton>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </TableContainer>

        <Dialog open={deleteDialogOpen} onClose={() => setDeleteDialogOpen(false)}>
          <DialogTitle>クライアントの削除</DialogTitle>
          <DialogContent>
            <Typography>
              クライアント「{selectedClient?.client_name}」を削除してもよろしいですか?
              この操作は取り消せません。
            </Typography>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setDeleteDialogOpen(false)}>キャンセル</Button>
            <Button onClick={handleDelete} color="error" variant="contained">
              削除
            </Button>
          </DialogActions>
        </Dialog>
      </Box>
    </AdminLayoutWrapper>
  );
}
