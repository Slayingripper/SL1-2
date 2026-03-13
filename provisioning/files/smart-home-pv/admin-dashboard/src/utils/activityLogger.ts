import { useEffect } from 'react';
import axios from 'axios';

type ActivityValue = string | number | boolean | null | undefined;

interface ActivityEvent {
  action: string;
  page: string;
  eventType?: string;
  target?: string;
  actor?: string;
  details?: Record<string, ActivityValue>;
}

const SENSITIVE_FIELD_PATTERN = /(pass(word)?|secret|token|auth)/i;

const truncate = (value: string, maxLength = 120) => {
  if (value.length <= maxLength) {
    return value;
  }
  return `${value.slice(0, maxLength - 3)}...`;
};

const toActionName = (value: string, fallback: string) => {
  const normalized = value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 80);
  return normalized || fallback;
};

const getElementLabel = (element: HTMLElement) => {
  const label =
    element.getAttribute('aria-label') ||
    element.getAttribute('title') ||
    element.getAttribute('data-log-label') ||
    element.textContent ||
    element.getAttribute('name') ||
    element.getAttribute('id') ||
    element.tagName;
  return truncate(label.trim(), 100);
};

const getElementTarget = (element: HTMLElement) => {
  const parts = [element.tagName.toLowerCase()];
  if (element.id) {
    parts.push(`#${element.id}`);
  }
  if (element.classList.length > 0) {
    parts.push(`.${Array.from(element.classList).slice(0, 2).join('.')}`);
  }
  return truncate(parts.join(''), 150);
};

const getFieldIdentifier = (element: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement) => {
  const placeholder = 'placeholder' in element ? element.placeholder : '';
  return truncate(
    element.name || element.id || element.getAttribute('aria-label') || placeholder || element.tagName.toLowerCase(),
    80,
  );
};

const getChangeValue = (element: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement) => {
  const field = getFieldIdentifier(element);
  const type = element instanceof HTMLInputElement ? element.type : element.tagName.toLowerCase();

  if (SENSITIVE_FIELD_PATTERN.test(field) || SENSITIVE_FIELD_PATTERN.test(type)) {
    return '[redacted]';
  }

  if (element instanceof HTMLInputElement && (type === 'checkbox' || type === 'radio')) {
    return element.checked ? 'checked' : 'unchecked';
  }

  if (type === 'number' || element instanceof HTMLSelectElement) {
    return truncate(String(element.value), 80);
  }

  return 'updated';
};

export const logAdminActivity = async (event: ActivityEvent, token?: string | null) => {
  try {
    await axios.post(
      '/api/admin/activity',
      {
        action: event.action,
        event_type: event.eventType || 'activity',
        page: event.page,
        target: event.target,
        actor: event.actor,
        details: event.details || {},
      },
      token
        ? {
            headers: {
              Authorization: `Bearer ${token}`,
            },
          }
        : undefined,
    );
  } catch (error) {
    console.debug('Admin activity log request failed:', error);
  }
};

export const useAdminActivityCapture = (page: string, token?: string | null) => {
  useEffect(() => {
    void logAdminActivity(
      {
        action: 'page_view',
        eventType: 'page_view',
        page,
        details: {
          view: page,
        },
      },
      token,
    );

    const onClick = (event: MouseEvent) => {
      const element = (event.target as HTMLElement | null)?.closest(
        'button, a, [role="button"], input[type="button"], input[type="submit"]',
      ) as HTMLElement | null;

      if (!element) {
        return;
      }

      const label = getElementLabel(element);
      const href = element instanceof HTMLAnchorElement ? element.href : undefined;
      const component = element.getAttribute('data-log-component') || undefined;
      const action = element.getAttribute('data-log-action') || `${toActionName(label, 'ui_action')}_clicked`;

      void logAdminActivity(
        {
          action,
          eventType: 'click',
          page,
          target: getElementTarget(element),
          details: {
            label,
            href: href ? truncate(href, 160) : undefined,
            component,
            control: element.tagName.toLowerCase(),
          },
        },
        token,
      );
    };

    const onSubmit = (event: Event) => {
      const form = event.target as HTMLFormElement | null;
      if (!form) {
        return;
      }

      const formName = truncate(
        form.getAttribute('aria-label') || form.getAttribute('name') || form.id || form.className || 'form',
        100,
      );

      void logAdminActivity(
        {
          action: `${toActionName(formName, 'form')}_submitted`,
          eventType: 'submit',
          page,
          target: formName,
          details: {
            form: formName,
          },
        },
        token,
      );
    };

    const onChange = (event: Event) => {
      const field = event.target as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement | null;
      if (!field || !(field instanceof HTMLInputElement || field instanceof HTMLSelectElement || field instanceof HTMLTextAreaElement)) {
        return;
      }

      const fieldName = getFieldIdentifier(field);
      const fieldType = field instanceof HTMLInputElement ? field.type : field.tagName.toLowerCase();
      const value = getChangeValue(field);

      void logAdminActivity(
        {
          action: `${toActionName(fieldName, 'field')}_changed`,
          eventType: 'change',
          page,
          target: fieldName,
          details: {
            field: fieldName,
            field_type: fieldType,
            value,
          },
        },
        token,
      );
    };

    document.addEventListener('click', onClick, true);
    document.addEventListener('submit', onSubmit, true);
    document.addEventListener('change', onChange, true);

    return () => {
      document.removeEventListener('click', onClick, true);
      document.removeEventListener('submit', onSubmit, true);
      document.removeEventListener('change', onChange, true);
    };
  }, [page, token]);
};