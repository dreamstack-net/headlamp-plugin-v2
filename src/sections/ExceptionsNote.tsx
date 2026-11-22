import { Typography } from '@mui/material';

/** Says that the exceptions could not be read, under counts of failed controls. */
export function ExceptionsNote(props: Readonly<{ error?: string }>) {
  if (!props.error) return null;
  return (
    <Typography variant="caption" color="text.secondary" component="div">
      Unable to read the security exceptions: {props.error}. Controls that exceptions cover may be
      counted as failed.
    </Typography>
  );
}
