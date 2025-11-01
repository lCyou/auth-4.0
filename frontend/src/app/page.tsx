'use client';

import { useState } from 'react';
import Container from '@mui/material/Container';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';

export default function Home() {
  const [message, setMessage] = useState('');

  const handleClick = async () => {
    try {
      const response = await fetch('http://localhost:8080/ping');
      const data = await response.json();
      setMessage(data.message);
    } catch (error) {
      setMessage('Failed to fetch');
      console.error('Error fetching from backend:', error);
    }
  };

  return (
    <Container maxWidth="sm">
      <Box
        sx={{
          my: 4,
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
          alignItems: 'center',
        }}
      >
        <Typography variant="h4" component="h1" sx={{ mb: 2 }}>
          OpenIDaaS Project
        </Typography>
        <Button variant="contained" onClick={handleClick}>
          Ping Backend
        </Button>
        {message && (
          <Typography sx={{ mt: 2 }}>
            Backend response: <strong>{message}</strong>
          </Typography>
        )}
      </Box>
    </Container>
  );
}