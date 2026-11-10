import { createFileRoute } from '@tanstack/react-router';
import { EnrollHost } from '@/components/Enroll/EnrollHost';

export const Route = createFileRoute('/_authed/enroll')({ component: EnrollHost });
