import Editor, { OnMount } from '@monaco-editor/react';
import { useEditorTheme } from '../common/theme';

/** A code editor of Monaco, as the editor component hands it over when it mounts. */
export type CodeEditor = Parameters<OnMount>[0];

export function MonacoEditor(
  props: Readonly<{
    editorRef?: React.MutableRefObject<CodeEditor | null>;
    language: string;
    defaultValue: string;
    height: number;
    onChange: (value: string) => void;
  }>
) {
  const { editorRef, language, defaultValue, height, onChange } = props;
  const editorTheme = useEditorTheme();
  return (
    <Editor
      language={language}
      defaultValue={defaultValue}
      height={height}
      theme={editorTheme}
      onMount={editor => {
        if (editorRef) editorRef.current = editor;
      }}
      onChange={(value: string | undefined) => onChange(value ?? '')}
      options={{ minimap: { enabled: false }, scrollBeyondLastLine: false }}
    />
  );
}
