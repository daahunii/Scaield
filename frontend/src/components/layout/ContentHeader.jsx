export function ContentHeader({ title, description, actions }) {
  return (
    <header className="content-header">
      <div className="content-header-title">
        <h2>{title}</h2>
        <p>{description}</p>
      </div>
      {actions}
    </header>
  );
}
