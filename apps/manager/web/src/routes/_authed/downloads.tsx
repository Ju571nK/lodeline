import { createFileRoute } from '@tanstack/react-router';
import { Downloads } from '@/components/Downloads/Downloads';

export const Route = createFileRoute('/_authed/downloads')({ component: Downloads });
