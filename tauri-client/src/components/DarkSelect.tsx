import React, { useEffect, useMemo, useRef, useState } from "react";
import { FaChevronDown } from "react-icons/fa";

export type SelectOption = {
  value: string;
  label: string;
  meta?: string;
};

type DarkSelectProps = {
  value: string;
  options: SelectOption[];
  onChange: (value: string) => void;
  placeholder?: string;
  disabled?: boolean;
};

export function DarkSelect({ value, options, onChange, placeholder = "Select", disabled = false }: DarkSelectProps) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const selected = useMemo(() => options.find((option) => option.value === value), [options, value]);

  useEffect(() => {
    function closeOnOutsideClick(event: MouseEvent) {
      if (!rootRef.current?.contains(event.target as Node)) {
        setOpen(false);
      }
    }

    window.addEventListener("mousedown", closeOnOutsideClick);
    return () => window.removeEventListener("mousedown", closeOnOutsideClick);
  }, []);

  return (
    <div className={`dark-select ${open ? "open" : ""} ${disabled ? "disabled" : ""}`} ref={rootRef}>
      <button
        type="button"
        className="dark-select-trigger"
        disabled={disabled}
        onClick={() => setOpen((current) => !current)}
      >
        <span>
          {selected ? selected.label : placeholder}
          {selected?.meta ? <small>{selected.meta}</small> : null}
        </span>
        <FaChevronDown size={11} />
      </button>
      {open ? (
        <div className="dark-select-menu">
          {options.map((option) => (
            <button
              type="button"
              key={option.value}
              className={option.value === value ? "selected" : ""}
              onClick={() => {
                onChange(option.value);
                setOpen(false);
              }}
            >
              <span>{option.label}</span>
              {option.meta ? <small>{option.meta}</small> : null}
            </button>
          ))}
        </div>
      ) : null}
    </div>
  );
}
