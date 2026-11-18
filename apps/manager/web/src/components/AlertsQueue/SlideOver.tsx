import { Link } from '@tanstack/react-router';
import { ChevronLeft, ChevronRight, Maximize2 } from 'lucide-react';
import { type KeyboardEvent, type PointerEvent, useEffect, useRef } from 'react';
import type { EventWithTriage } from '@/api/fleet';
import { AlertBadges, AlertDetail, alertTitle } from '@/components/AlertsQueue/AlertDetail';
import { Button } from '@/components/ui/button';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import { useDrawerWidth } from '@/hooks/useDrawerWidth';
import type { AlertsSearch } from '@/lib/alertsSearch';

/** Where the open alert sits in the list behind the drawer. */
export interface DrawerPosition {
  index: number;
  total: number;
  /** More rows can load, so the total is only the loaded rows. */
  partial?: boolean;
  onPrev: () => void;
  onNext: () => void;
}

interface Props {
  /** The event being inspected, or null when nothing is selected. */
  event: EventWithTriage | null;
  /** The events of the collapsed row `event` stands for, newest first. */
  groupEvents?: EventWithTriage[];
  /** Closes the slide-over (e.g. by clearing the URL alert= param). */
  onClose: () => void;
  /** Imperative handle the parent can use to focus the assign input. */
  registerFocusAssign: (fn: () => void) => void;
  registerFocusNote: (fn: () => void) => void;
  /** Previous and next buttons with a "3 of 7" position, when a list is behind the drawer. */
  position?: DrawerPosition;
  /** The list view to return to; gives the drawer an "Open full page" link. */
  fullPageSearch?: AlertsSearch;
}

const KEY_STEP = 20;
const KEY_STEP_LARGE = 100;

/**
 * Right-side slide-over: opens via the URL `?alert=:event_id` param, starts
 * wide on a large window, resizes by drag or arrow keys and remembers the
 * width per viewer. Under 900 px it takes the full width. Every action goes
 * through useTriage, which invalidates the Alerts queue cache so the row pill
 * updates immediately.
 */
export function SlideOver({
  event,
  groupEvents,
  onClose,
  registerFocusAssign,
  registerFocusNote,
  position,
  fullPageSearch,
}: Props) {
  const open = event !== null;
  const assignInputRef = useRef<HTMLInputElement | null>(null);
  const noteInputRef = useRef<HTMLTextAreaElement | null>(null);
  const drawer = useDrawerWidth();

  useEffect(() => {
    registerFocusAssign(() => assignInputRef.current?.focus());
    registerFocusNote(() => noteInputRef.current?.focus());
  }, [registerFocusAssign, registerFocusNote]);

  const onHandleKey = (e: KeyboardEvent<HTMLDivElement>) => {
    const step = e.shiftKey ? KEY_STEP_LARGE : KEY_STEP;
    if (e.key === 'ArrowLeft') drawer.resizeTo(drawer.width + step, true);
    else if (e.key === 'ArrowRight') drawer.resizeTo(drawer.width - step, true);
    else return;
    e.preventDefault();
  };
  const onHandleDown = (e: PointerEvent<HTMLDivElement>) => {
    e.currentTarget.setPointerCapture(e.pointerId);
  };
  const onHandleMove = (e: PointerEvent<HTMLDivElement>) => {
    if (e.currentTarget.hasPointerCapture(e.pointerId)) {
      drawer.resizeTo(window.innerWidth - e.clientX, false);
    }
  };
  const onHandleUp = (e: PointerEvent<HTMLDivElement>) => {
    if (e.currentTarget.hasPointerCapture(e.pointerId)) {
      e.currentTarget.releasePointerCapture(e.pointerId);
      drawer.resizeTo(window.innerWidth - e.clientX, true);
    }
  };

  return (
    <Sheet
      open={open}
      onOpenChange={(next) => {
        if (!next) onClose();
      }}
    >
      <SheetContent
        side="right"
        overlayClassName="bg-black/40"
        style={{ width: drawer.full ? '100vw' : drawer.width, maxWidth: '100vw' }}
        className="bg-bg-surface p-0 border-l border-border"
      >
        {!drawer.full && (
          // biome-ignore lint/a11y/useSemanticElements: a focusable, draggable window splitter is not an <hr>
          <div
            role="separator"
            aria-orientation="vertical"
            aria-label="Resize alert panel"
            aria-valuemin={drawer.min}
            aria-valuemax={drawer.max}
            aria-valuenow={drawer.width}
            tabIndex={0}
            onKeyDown={onHandleKey}
            onPointerDown={onHandleDown}
            onPointerMove={onHandleMove}
            onPointerUp={onHandleUp}
            className="absolute inset-y-0 left-0 z-10 w-1.5 cursor-col-resize touch-none hover:bg-accent/40 focus-visible:bg-accent/60 focus-visible:outline-none"
          />
        )}
        {event ? (
          <div className="flex h-full flex-col">
            <div className="border-b border-border-subtle px-5 py-3 pr-12">
              {(position || fullPageSearch) && (
                <div className="mb-2 flex items-center gap-2">
                  {position && <PositionControls position={position} />}
                  {fullPageSearch && (
                    <Link
                      to="/alerts/$eventId"
                      params={{ eventId: event.event_id }}
                      search={{ ...fullPageSearch, alert: undefined }}
                      className="ml-auto inline-flex items-center gap-1 text-xs text-accent hover:underline"
                    >
                      <Maximize2 className="h-3 w-3" aria-hidden />
                      Open full page
                    </Link>
                  )}
                </div>
              )}
              <SheetHeader className="p-0">
                <SheetTitle className="text-base font-semibold text-text-primary">
                  {alertTitle(event)}
                </SheetTitle>
                <SheetDescription className="text-xs text-text-muted">
                  event_id{' '}
                  <code className="font-mono [overflow-wrap:anywhere]">{event.event_id}</code>
                </SheetDescription>
              </SheetHeader>
              <div className="mt-2">
                <AlertBadges event={event} />
              </div>
            </div>
            <div className="flex-1 overflow-y-auto px-5 py-4">
              <AlertDetail
                event={event}
                groupEvents={groupEvents}
                assignInputRef={assignInputRef}
                noteInputRef={noteInputRef}
              />
            </div>
          </div>
        ) : (
          <SheetHeader className="p-4">
            <SheetTitle>No alert selected</SheetTitle>
            <SheetDescription>Open one from the queue.</SheetDescription>
          </SheetHeader>
        )}
      </SheetContent>
    </Sheet>
  );
}

function PositionControls({ position }: { position: DrawerPosition }) {
  const { index, total, partial, onPrev, onNext } = position;
  return (
    <div className="flex items-center gap-1.5">
      <Button
        size="sm"
        variant="secondary"
        aria-label="Previous alert"
        disabled={index <= 0}
        onClick={onPrev}
      >
        <ChevronLeft className="h-3.5 w-3.5" />
      </Button>
      <span data-testid="alert-position" className="text-xs tabular-nums text-text-muted">
        {index + 1} of {total}
        {partial && ' loaded'}
      </span>
      <Button
        size="sm"
        variant="secondary"
        aria-label="Next alert"
        disabled={index >= total - 1}
        onClick={onNext}
      >
        <ChevronRight className="h-3.5 w-3.5" />
      </Button>
    </div>
  );
}
